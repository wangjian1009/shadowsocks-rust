use async_trait::async_trait;
use spin::Mutex;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
    task::JoinHandle,
};

use crate::{net::UdpSocket, ServerAddr};
use tracing::Instrument;

#[cfg(feature = "rate-limit")]
use crate::transport::RateLimiter;

use super::{
    super::{Acceptor, DeviceOrGuard, StreamConnection},
    MkcpConfig, StatisticStat,
};

use super::{
    connection::{MkcpConnMetadata, MkcpConnWay},
    io::{MkcpPacketReader, MkcpPacketWriter},
    new_error,
    segment::{Command, Segment},
    MkcpConnection,
};

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
struct MkcpConnectionID {
    pub remote: SocketAddr,
    pub conv: u16,
}

struct MkcpAcceptorCtx {
    config: Arc<MkcpConfig>,
    local_addr: SocketAddr,
    statistic: Option<Arc<StatisticStat>>,
    connections: Mutex<HashMap<MkcpConnectionID, Arc<MkcpConnection>>>,
}

pub struct MkcpAcceptor {
    context: Arc<MkcpAcceptorCtx>,
    rx: tokio::sync::Mutex<mpsc::Receiver<MkcpConnectionID>>,
    recv_task: JoinHandle<()>,
}

impl MkcpAcceptor {
    pub fn new(
        config: Arc<MkcpConfig>,
        local_addr: SocketAddr,
        pr: Arc<UdpSocket>,
        pw: Arc<UdpSocket>,
        statistic: Option<Arc<StatisticStat>>,
    ) -> Self {
        let header = config.create_header().map(Arc::new);
        let security = Arc::new(config.create_security());

        let (tx, rx) = mpsc::channel(1);

        let context = MkcpAcceptorCtx {
            config,
            local_addr,
            statistic,
            connections: Mutex::new(HashMap::new()),
        };
        let context = Arc::new(context);

        let pr = MkcpPacketReader::new(pr, header.clone(), Some(security.clone()));
        let pw = MkcpPacketWriter::new(pw, header, Some(security));

        let recv_task = {
            let context = context.clone();
            tokio::spawn(async move {
                match Self::handle_incoming(context.clone(), tx, pr, pw).await {
                    Ok(..) => {
                        tracing::trace!("MkcpAcceptor: {}: handler incoming completed", context.local_addr);
                    }
                    Err(err) => {
                        tracing::error!("MkcpAcceptor: {}: handler incoming error: {}", context.local_addr, err);
                    }
                }
            }.in_current_span())
        };

        MkcpAcceptor {
            context,
            rx: tokio::sync::Mutex::new(rx),
            recv_task,
        }
    }

    #[inline]
    pub fn statistic(&self) -> Option<Arc<StatisticStat>> {
        self.context.statistic.clone()
    }

    async fn handle_incoming(
        context: Arc<MkcpAcceptorCtx>,
        new_conn_tx: mpsc::Sender<MkcpConnectionID>,
        mut reader: MkcpPacketReader,
        writer: MkcpPacketWriter,
    ) -> io::Result<()> {
        let writer = Arc::new(writer);
        let (remove_conn_tx, mut remove_conn_rx) = mpsc::channel(1);
        let remove_conn_tx = Arc::new(remove_conn_tx);
        loop {
            tokio::select! {
                r = reader.read() => {
                    match r {
                        Ok((segments, addr)) => Self::on_receive(context.as_ref(), &new_conn_tx, &remove_conn_tx, &writer, segments, addr).await?,
                        Err(err) => {
                            tracing::error!("MkcpAcceptor {}: read error: {}", context.local_addr, err);
                        }
                    }
                }
                id = remove_conn_rx.recv() => {
                    if let Some(id) = id {
                        context.connections.lock().remove(&id);
                    }
                    else {
                        tracing::error!("MkcpAcceptor {}: remove conn rx recv none", context.local_addr);
                    }
                }
            }

            tokio::task::yield_now().await;
        }
    }

    async fn on_receive(
        context: &MkcpAcceptorCtx,
        new_conn_tx: &mpsc::Sender<MkcpConnectionID>,
        remove_conn_tx: &Arc<mpsc::Sender<MkcpConnectionID>>,
        writer: &Arc<MkcpPacketWriter>,
        segments: Vec<Segment>,
        src: SocketAddr,
    ) -> io::Result<()> {
        if segments.is_empty() {
            return Err(new_error(format!("discarding invalid payload from {src}")));
        }

        let conv = segments[0].conv;

        let id = MkcpConnectionID { remote: src, conv };

        let (connection, is_new) = {
            let mut connections = context.connections.lock();

            match connections.get(&id) {
                Some(c) => (c.clone(), false),
                None => match &segments[0].cmd() {
                    Command::Terminate => return Ok(()),
                    _ => {
                        let remove_fn = {
                            let remove_conn_tx = remove_conn_tx.clone();
                            let id = id.clone();
                            move || {
                                let id = id.clone();
                                let remove_conn_tx = remove_conn_tx.clone();
                                tokio::spawn(async move {
                                    if let Err(err) = remove_conn_tx.send(id).await {
                                        tracing::error!("MkcpAcceptor: {}", err);
                                    }
                                }.in_current_span());
                            }
                        };

                        let connection = MkcpConnection::new(
                            context.config.clone(),
                            MkcpConnMetadata {
                                way: MkcpConnWay::Incoming,
                                local_addr: context.local_addr,
                                remote_addr: ServerAddr::SocketAddr(id.remote),
                                conversation: conv,
                            },
                            Some(Box::new(remove_fn)),
                            writer.clone(),
                            context.statistic.clone(),
                        );

                        let connection = Arc::new(connection);
                        connections.insert(id.clone(), connection.clone());
                        (connection, true)
                    }
                },
            }
        };

        connection.input(segments);

        if is_new {
            if let Err(err) = new_conn_tx.send(id).await {
                return Err(new_error(format!(
                    "discarding new connection {} from {}",
                    connection.meta().conversation,
                    err
                )));
            }
        }

        Ok(())
    }

    pub fn active_connections(&self) -> usize {
        self.context.connections.lock().len()
    }
}

impl Drop for MkcpAcceptor {
    fn drop(&mut self) {
        self.recv_task.abort()
    }
}

#[async_trait]
impl Acceptor for MkcpAcceptor {
    type TS = MkcpAcceptorConnection;

    async fn accept(&mut self) -> io::Result<(Self::TS, Option<SocketAddr>)> {
        loop {
            let id = match self.rx.lock().await.recv().await {
                Some(id) => id,
                None => continue,
            };

            let connection = match self.context.connections.lock().get(&id) {
                Some(connection) => connection.clone(),
                None => continue,
            };

            let remote_addr = id.remote;

            let connection = Self::TS {
                context: self.context.clone(),
                id,
                inner: connection,
            };

            return Ok((connection, Some(remote_addr)));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.context.local_addr)
    }
}

pub struct MkcpAcceptorConnection {
    context: Arc<MkcpAcceptorCtx>,
    id: MkcpConnectionID,
    inner: Arc<MkcpConnection>,
}

impl Drop for MkcpAcceptorConnection {
    fn drop(&mut self) {
        let connection = {
            let connections = self.context.connections.lock();
            connections.get(&self.id).cloned()
        };

        if let Some(connection) = connection {
            match connection.close() {
                Ok(()) => tracing::trace!("#{}: close: success", connection.meta()),
                Err(err) => tracing::debug!("#{}: close: {:?}", connection.meta(), err),
            }
        }
    }
}

#[async_trait]
impl StreamConnection for MkcpAcceptorConnection {
    #[inline]
    fn check_connected(&self) -> bool {
        true
    }

    #[cfg(feature = "rate-limit")]
    #[inline]
    fn set_rate_limit(&mut self, _rate_limit: Option<Arc<RateLimiter>>) {
        tracing::debug!("#{}: set_rate_limit: ignore", 1)
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        unimplemented!()
    }
}

impl AsyncRead for MkcpAcceptorConnection {
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for MkcpAcceptorConnection {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
