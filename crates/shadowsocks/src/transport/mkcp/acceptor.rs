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

use crate::ServerAddr;

#[cfg(feature = "rate-limit")]
use crate::transport::RateLimiter;

use super::{
    super::{Acceptor, Connection, DeviceOrGuard, DummyPacket, PacketRead, PacketWrite, StreamConnection},
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
    pub remote: ServerAddr,
    pub conv: u16,
}

struct MkcpAcceptorCtx<PW: PacketWrite> {
    config: Arc<MkcpConfig>,
    local_addr: SocketAddr,
    statistic: Option<Arc<StatisticStat>>,
    connections: Mutex<HashMap<MkcpConnectionID, Arc<MkcpConnection<PW>>>>,
}

pub struct MkcpAcceptor<PW: PacketWrite> {
    context: Arc<MkcpAcceptorCtx<PW>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<MkcpConnectionID>>,
    recv_task: JoinHandle<()>,
}

impl<PW> MkcpAcceptor<PW>
where
    PW: PacketWrite + 'static,
{
    pub fn new<PR>(
        config: Arc<MkcpConfig>,
        local_addr: SocketAddr,
        pr: PR,
        pw: PW,
        statistic: Option<Arc<StatisticStat>>,
    ) -> Self
    where
        PR: PacketRead + 'static,
    {
        let header = match config.create_header() {
            Some(header) => Some(Arc::new(header)),
            None => None,
        };
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
            })
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

    async fn handle_incoming<PR>(
        context: Arc<MkcpAcceptorCtx<PW>>,
        new_conn_tx: mpsc::Sender<MkcpConnectionID>,
        mut reader: MkcpPacketReader<PR>,
        writer: MkcpPacketWriter<PW>,
    ) -> io::Result<()>
    where
        PR: PacketRead,
    {
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
        context: &MkcpAcceptorCtx<PW>,
        new_conn_tx: &mpsc::Sender<MkcpConnectionID>,
        remove_conn_tx: &Arc<mpsc::Sender<MkcpConnectionID>>,
        writer: &Arc<MkcpPacketWriter<PW>>,
        segments: Vec<Segment>,
        src: ServerAddr,
    ) -> io::Result<()> {
        if segments.len() == 0 {
            return Err(new_error(format!("discarding invalid payload from {}", src)));
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
                                });
                            }
                        };

                        let connection = MkcpConnection::new(
                            context.config.clone(),
                            MkcpConnMetadata {
                                way: MkcpConnWay::Incoming,
                                local_addr: ServerAddr::SocketAddr(context.local_addr.clone()),
                                remote_addr: id.remote.clone(),
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

impl<PW> Drop for MkcpAcceptor<PW>
where
    PW: PacketWrite,
{
    fn drop(&mut self) {
        self.recv_task.abort()
    }
}

#[async_trait]
impl<PW: PacketWrite + 'static> Acceptor for MkcpAcceptor<PW> {
    type PR = DummyPacket;
    type PW = DummyPacket;
    type TS = MkcpAcceptorConnection<PW>;

    async fn accept(&mut self) -> io::Result<(Connection<Self::TS, Self::PR, Self::PW>, Option<ServerAddr>)> {
        loop {
            let id = match self.rx.lock().await.recv().await {
                Some(id) => id,
                None => continue,
            };

            let connection = match self.context.connections.lock().get(&id) {
                Some(connection) => connection.clone(),
                None => continue,
            };

            let remote_addr = id.remote.clone();

            let connection = Self::TS {
                context: self.context.clone(),
                id,
                inner: connection,
            };

            return Ok((Connection::Stream(connection), Some(remote_addr)));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.context.local_addr.clone())
    }
}

pub struct MkcpAcceptorConnection<PW>
where
    PW: PacketWrite + 'static,
{
    context: Arc<MkcpAcceptorCtx<PW>>,
    id: MkcpConnectionID,
    inner: Arc<MkcpConnection<PW>>,
}

impl<PW> Drop for MkcpAcceptorConnection<PW>
where
    PW: PacketWrite + 'static,
{
    fn drop(&mut self) {
        let connection = {
            let connections = self.context.connections.lock();
            connections.get(&self.id).map(|e| e.clone())
        };

        match connection {
            Some(connection) => match connection.close() {
                Ok(()) => tracing::trace!("#{}: close: success", connection.meta()),
                Err(err) => tracing::debug!("#{}: close: {:?}", connection.meta(), err),
            },
            None => {}
        }
    }
}

#[async_trait]
impl<PW> StreamConnection for MkcpAcceptorConnection<PW>
where
    PW: PacketWrite + 'static,
{
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

impl<PW> AsyncRead for MkcpAcceptorConnection<PW>
where
    PW: PacketWrite + 'static,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_read(cx, buf)
    }
}

impl<PW> AsyncWrite for MkcpAcceptorConnection<PW>
where
    PW: PacketWrite + 'static,
{
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
