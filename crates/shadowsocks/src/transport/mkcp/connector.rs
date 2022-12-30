use async_trait::async_trait;
use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    task::{self, Poll},
};

use tokio::sync::mpsc;

use crate::{net::ConnectOpts, net::UdpSocket, transport::DeviceOrGuard, ServerAddr};

use super::{
    super::{Connector, StreamConnection},
    connection::MkcpState,
    io::{MkcpPacketReader, MkcpPacketWriter},
    MkcpConfig, MkcpConnMetadata, MkcpConnWay, StatisticStat,
};

use super::MkcpConnection;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

#[cfg(feature = "rate-limit")]
use crate::transport::RateLimiter;

pub struct MkcpConnector {
    config: Arc<MkcpConfig>,
    next_conv: AtomicU16,
    statistic: Option<Arc<StatisticStat>>,
}

impl MkcpConnector {
    pub fn new(config: Arc<MkcpConfig>, statistic: Option<Arc<StatisticStat>>) -> Self {
        Self {
            config,
            statistic,
            next_conv: AtomicU16::new(rand::random()),
        }
    }
}

#[async_trait]
impl Connector for MkcpConnector {
    type TS = MkcpConnectorConnection;

    async fn connect(&self, addr: &ServerAddr, connect_opts: &ConnectOpts) -> io::Result<Self::TS> {
        let addr = match addr {
            ServerAddr::SocketAddr(addr) => addr,
            ServerAddr::DomainName(..) => return Err(io::Error::new(io::ErrorKind::Other, "not support domain addr")),
        };

        let socket = UdpSocket::connect_with_opts(addr, connect_opts).await?;
        let local_addr = socket.local_addr()?;
        let r = Arc::new(socket);
        let w = r.clone();

        let meta = MkcpConnMetadata {
            way: MkcpConnWay::Outgoing,
            local_addr,
            remote_addr: ServerAddr::SocketAddr(addr.clone()),
            conversation: self.next_conv.fetch_add(1, Ordering::SeqCst),
        };

        Ok(MkcpConnectorConnection::new(
            self.config.clone(),
            meta,
            r,
            w,
            self.statistic.clone(),
        ))
    }
}

pub struct MkcpConnectorConnection {
    inner: Arc<MkcpConnection>,
    _recv_task: Arc<JoinHandle<()>>,
}

impl MkcpConnectorConnection {
    fn new(
        config: Arc<MkcpConfig>,
        meta: MkcpConnMetadata,
        r: Arc<UdpSocket>,
        w: Arc<UdpSocket>,
        statistic: Option<Arc<StatisticStat>>,
    ) -> Self {
        let header = config.create_header().map(Arc::new);
        let security = Arc::new(config.create_security());
        let r = MkcpPacketReader::new(r, header.clone(), Some(security.clone()));
        let w = MkcpPacketWriter::new(w, header, Some(security));

        let (remove_conn_tx, remove_conn_rx) = mpsc::channel(1);

        let remove_fn = {
            let remove_conn_tx = Arc::new(remove_conn_tx);
            let id = meta.conversation;
            move || {
                let remove_conn_tx = remove_conn_tx.clone();
                tokio::spawn(async move {
                    if let Err(err) = remove_conn_tx.send(id).await {
                        tracing::error!("MkcpConnector: {}", err);
                    }
                });
            }
        };

        let connection = MkcpConnection::new(config, meta, Some(Box::new(remove_fn)), Arc::new(w), statistic);
        let connection = Arc::new(connection);

        let recv_task = {
            let connection = connection.clone();
            tokio::spawn(async move { Self::handle_incoming(r, remove_conn_rx, connection).await })
        };

        Self {
            inner: connection,
            _recv_task: Arc::new(recv_task),
        }
    }

    #[inline]
    pub fn state(&self) -> MkcpState {
        self.inner.state()
    }

    #[inline]
    pub fn close(&self) -> io::Result<()> {
        self.inner.close()
    }

    async fn handle_incoming(
        mut reader: MkcpPacketReader,
        mut remove_conn_rx: mpsc::Receiver<u16>,
        connection: Arc<MkcpConnection>,
    ) {
        loop {
            tokio::select! {
                r = reader.read() => {
                    match r {
                        Ok((segments, _addr)) => connection.input(segments),
                        Err(err) => {
                            tracing::error!("#{}: handler incoming error: {}", connection.meta(), err);
                            return;
                        }
                    };
                }
                id = remove_conn_rx.recv() => {
                    if let Some(_id) = id {
                        tracing::trace!("#{}: handle incoming recv recv", connection.meta());
                        break;
                    }
                    else {
                        tracing::error!("#{}: remove conn rx recv none", connection.meta());
                    }
                }
            }

            tokio::task::yield_now().await;
        }

        tracing::trace!("#{}: handle incoming stoped", connection.meta());
    }
}

impl Drop for MkcpConnectorConnection {
    fn drop(&mut self) {
        match self.inner.close() {
            Ok(()) => tracing::trace!("#{}: close: success", self.inner.meta()),
            Err(err) => tracing::debug!("#{}: close: {:?}", self.inner.meta(), err),
        }
    }
}

#[async_trait]
impl StreamConnection for MkcpConnectorConnection {
    #[inline]
    fn check_connected(&self) -> bool {
        true
    }

    #[cfg(feature = "rate-limit")]
    #[inline]
    fn set_rate_limit(&mut self, _rate_limit: Option<Arc<RateLimiter>>) {
        tracing::info!(
            "#{}: rate-limit: ignore rate limit for kcp connection",
            self.inner.meta()
        );
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        unreachable!()
    }
}

impl AsyncRead for MkcpConnectorConnection {
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for MkcpConnectorConnection {
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

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut task::Context<'_>,
        _bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        unreachable!()
    }
}
