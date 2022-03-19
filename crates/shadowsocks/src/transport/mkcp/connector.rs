use async_trait::async_trait;
use std::{
    io::{self, IoSlice},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    task::{self, Poll},
};

use tokio::sync::mpsc;

use crate::{
    net::{ConnectOpts, Destination},
    transport::{PacketRead, PacketWrite},
    ServerAddr,
};

use super::{
    super::{Connection, Connector, DummyPacket, StreamConnection},
    connection::MkcpState,
    io::{MkcpPacketReader, MkcpPacketWriter},
    new_error, MkcpConfig, MkcpConnMetadata, MkcpConnWay, StatisticStat,
};

use super::MkcpConnection;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

#[cfg(feature = "rate-limit")]
use crate::transport::RateLimiter;

pub struct MkcpConnector<C>
where
    C: Connector,
{
    config: Arc<MkcpConfig>,
    next_conv: AtomicU16,
    inner: C,
    statistic: Option<Arc<StatisticStat>>,
}

impl<C> MkcpConnector<C>
where
    C: Connector,
{
    pub fn new(config: Arc<MkcpConfig>, inner: C, statistic: Option<Arc<StatisticStat>>) -> Self {
        Self {
            config,
            inner,
            statistic,
            next_conv: AtomicU16::new(rand::random()),
        }
    }
}

#[async_trait]
impl<C, PW> Connector for MkcpConnector<C>
where
    PW: PacketWrite + 'static,
    C: Connector + Connector<PW = PW>,
{
    type PR = DummyPacket;
    type PW = DummyPacket;
    type TS = MkcpConnectorConnection<C::PW>;

    async fn connect(
        &self,
        destination: &Destination,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Connection<Self::TS, Self::PR, Self::PW>> {
        match destination {
            Destination::Tcp(addr) => match self
                .inner
                .connect(
                    &Destination::Udp(match addr {
                        ServerAddr::SocketAddr(addr) => match addr {
                            SocketAddr::V4(..) => {
                                ServerAddr::SocketAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                            }
                            SocketAddr::V6(..) => {
                                ServerAddr::SocketAddr(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
                            }
                        },
                        ServerAddr::DomainName(..) => {
                            return Err(new_error("not support connect DomainName connection"))
                        }
                    }),
                    connect_opts,
                )
                .await?
            {
                Connection::Stream(_stream) => unreachable!(),
                Connection::Packet { r, w, local_addr } => {
                    let local_addr = match local_addr {
                        Destination::Udp(local_addr) => local_addr,
                        _ => unreachable!(),
                    };

                    let meta = MkcpConnMetadata {
                        way: MkcpConnWay::Outgoing,
                        local_addr,
                        remote_addr: addr.clone(),
                        conversation: self.next_conv.fetch_add(1, Ordering::SeqCst),
                    };

                    Ok(Connection::Stream(MkcpConnectorConnection::new(
                        self.config.clone(),
                        meta,
                        r,
                        w,
                        self.statistic.clone(),
                    )))
                }
            },
            Destination::Udp(..) => return Err(new_error("not support connect Udp connection")),
            #[cfg(unix)]
            Destination::Unix(..) => return Err(new_error("not support connect Unix stream")),
        }
    }
}

pub struct MkcpConnectorConnection<PW>
where
    PW: PacketWrite + 'static,
{
    inner: Arc<MkcpConnection<PW>>,
    _recv_task: Arc<JoinHandle<()>>,
}

impl<PW> MkcpConnectorConnection<PW>
where
    PW: PacketWrite + 'static,
{
    fn new<PR>(
        config: Arc<MkcpConfig>,
        meta: MkcpConnMetadata,
        r: PR,
        w: PW,
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
                        log::error!("MkcpConnector: {}", err);
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

    async fn handle_incoming<PR>(
        mut reader: MkcpPacketReader<PR>,
        mut remove_conn_rx: mpsc::Receiver<u16>,
        connection: Arc<MkcpConnection<PW>>,
    ) where
        PR: PacketRead,
    {
        loop {
            tokio::select! {
                r = reader.read() => {
                    match r {
                        Ok((segments, _addr)) => connection.input(segments),
                        Err(err) => {
                            log::error!("#{}: handler incoming error: {}", connection.meta(), err);
                            return;
                        }
                    };
                }
                id = remove_conn_rx.recv() => {
                    if let Some(_id) = id {
                        log::trace!("#{}: handle incoming recv recv", connection.meta());
                        break;
                    }
                    else {
                        log::error!("#{}: remove conn rx recv none", connection.meta());
                    }
                }

            }
        }

        log::trace!("#{}: handle incoming stoped", connection.meta());
    }
}

impl<PW> Drop for MkcpConnectorConnection<PW>
where
    PW: PacketWrite + 'static,
{
    fn drop(&mut self) {
        if let Err(err) = self.inner.close() {
            log::debug!("#{}: close: {:?}", self.inner.meta(), err);
        }
    }
}

#[async_trait]
impl<PW> StreamConnection for MkcpConnectorConnection<PW>
where
    PW: PacketWrite + 'static,
{
    #[inline]
    fn local_addr(&self) -> io::Result<Destination> {
        Ok(Destination::Udp(self.inner.meta().local_addr.clone()))
    }

    #[inline]
    fn check_connected(&self) -> bool {
        true
    }

    #[cfg(feature = "rate-limit")]
    #[inline]
    fn set_rate_limit(&mut self, _rate_limit: Option<Arc<RateLimiter>>) {
        log::info!(
            "#{}: rate-limit: ignore rate limit for kcp connection",
            self.inner.meta()
        );
    }
}

impl<PW> AsyncRead for MkcpConnectorConnection<PW>
where
    PW: PacketWrite + 'static,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_read(cx, buf)
    }
}

impl<PW> AsyncWrite for MkcpConnectorConnection<PW>
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

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut task::Context<'_>,
        _bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        unreachable!()
    }
}
