use async_trait::async_trait;
use bytes::Bytes;
use cfg_if::cfg_if;
use std::{
    future::Future,
    io,
    net::{SocketAddr, SocketAddrV6},
    sync::Arc,
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{Receiver, Sender},
    time::Duration,
};

use shadowsocks::{
    lookup_then,
    net::{AddrFamily, FlowStat, TcpStream, UdpSocket},
    policy::{self, StreamAction},
    timeout::TimeoutTicker,
    ServerAddr,
};

use tracing::{error, info_span, trace, Instrument};

use crate::server::dns::run_dns_tcp_stream;

use super::context::ServiceContext;

#[cfg(feature = "rate-limit")]
use shadowsocks::transport::RateLimiter;

/// InConnectionGuard
pub struct InConnectionGuard {
    context: Arc<ServiceContext>,
    connection_ctx: (u32, bool),
}

impl policy::ConnectionGuard for InConnectionGuard {}

impl Drop for InConnectionGuard {
    fn drop(&mut self) {
        let connection_ctx = self.connection_ctx;
        let context = self.context.clone();
        tokio::spawn(
            async move {
                context
                    .connection_stat_ref()
                    .remove_in_connection(&connection_ctx.0, connection_ctx.1)
                    .await;
            }
            .in_current_span(),
        );
    }
}

/// OutConnectionGuard
pub struct OutConnectionGuard {
    _guard: super::connection::OutConnectionGuard,
}

impl OutConnectionGuard {
    pub fn new(guard: super::connection::OutConnectionGuard) -> Self {
        Self { _guard: guard }
    }
}

impl policy::ConnectionGuard for OutConnectionGuard {}

cfg_if! {
    if #[cfg(feature = "server-mock")] {
        use super::context::ServerMockProtocol;

        /// LocalProcessor
        pub struct LocalProcessor {
            context: Arc<ServiceContext>,
            protocol: ServerMockProtocol,
            _remote_guard: InConnectionGuard,
            #[cfg(feature = "statistics")]
            _out_conn_guard: shadowsocks::statistics::ConnGuard,
        }

        impl LocalProcessor {
            pub fn new (context: Arc<ServiceContext>, protocol: ServerMockProtocol, guard: InConnectionGuard,
                        #[cfg(feature = "statistics")] _out_conn_guard: shadowsocks::statistics::ConnGuard) -> Self {
                Self { context, protocol, _remote_guard: guard, #[cfg(feature = "statistics")] _out_conn_guard }
            }
        }

        #[async_trait]
        impl policy::LocalProcessor for LocalProcessor {
            async fn process(
                &self,
                mut r: Box<dyn AsyncRead + Send + Unpin>,
                mut w: Box<dyn AsyncWrite + Send + Unpin>,
                timeout_ticker: Option<TimeoutTicker>,
            ) -> io::Result<()>
            {
                match self.protocol {
                    ServerMockProtocol::DNS => {
                        run_dns_tcp_stream(
                            self.context.dns_resolver(),
                            &mut r,
                            &mut w,
                            timeout_ticker,
                        )
                        .instrument(info_span!("dns"))
                        .await?;
                        Ok(())
                    }
                }
            }
        }
    }
}

pub struct ServerPolicy {
    context: Arc<ServiceContext>,
    connect_timeout: Duration,
}

impl ServerPolicy {
    pub fn new(context: Arc<ServiceContext>, connect_timeout: Duration) -> Self {
        Self {
            context,
            connect_timeout,
        }
    }
}

#[async_trait]
impl policy::ServerPolicy for ServerPolicy {
    fn create_connection_flow_state_tcp(&self) -> Option<Arc<FlowStat>> {
        Some(self.context.flow_stat_tcp())
    }

    fn create_connection_flow_state_udp(&self) -> Option<Arc<FlowStat>> {
        Some(self.context.flow_stat_udp())
    }

    async fn create_out_connection(
        &self,
        source_addr: Option<&SocketAddr>,
        target_addr: ServerAddr,
        #[cfg(feature = "statistics")] bu_context: shadowsocks::statistics::BuContext,
    ) -> io::Result<(TcpStream, Box<dyn policy::ConnectionGuard>)> {
        let stream = timeout_fut(
            self.connect_timeout,
            shadowsocks::net::TcpStream::connect_remote_with_opts(
                self.context.context_ref(),
                target_addr.clone(),
                self.context.connect_opts_ref(),
            ),
        )
        .await?;

        Ok((
            stream,
            Box::new(OutConnectionGuard::new(
                self.context.connection_stat().add_out_connection(
                    source_addr,
                    &target_addr,
                    #[cfg(feature = "statistics")]
                    bu_context.clone(),
                ),
            )) as Box<dyn policy::ConnectionGuard>,
        ))
    }

    async fn create_out_udp_socket(&self) -> io::Result<Box<dyn policy::UdpSocket>> {
        Ok(Box::new(OutgoingUdpSocket::new(
            self.context.clone(),
            shadowsocks::relay::udprelay::MAXIMUM_UDP_PAYLOAD_SIZE,
        )) as Box<dyn policy::UdpSocket>)
    }

    async fn stream_check(
        &self,
        src_addr: Option<&SocketAddr>,
        target_addr: &ServerAddr,
        #[cfg(feature = "statistics")] bu_context: shadowsocks::statistics::BuContext,
    ) -> io::Result<policy::StreamAction> {
        // 后续支持不同地址的处理
        let src_addr = match src_addr {
            Some(src_addr) => src_addr,
            None => unreachable!(),
        };

        let connection_stat = self.context.connection_stat();

        let connection_ctx = match connection_stat
            .check_add_in_connection(src_addr.clone(), self.context.limit_connection_per_ip())
            .await
        {
            Ok((c, b)) => (c.id, b),
            Err(_err) => {
                match self.context.limit_connection_close_delay() {
                    None => error!(
                        "tcp server: from {} limit {} reached, close immediately",
                        src_addr,
                        self.context.limit_connection_per_ip().unwrap(),
                    ),
                    Some(delay) => {
                        error!(
                            "tcp server: from {} limit {} reached, close delay {:?}",
                            src_addr,
                            self.context.limit_connection_per_ip().unwrap(),
                            delay
                        );
                        tokio::time::sleep(*delay).await;
                    }
                }
                return Ok(policy::StreamAction::ConnectionLimited);
            }
        };

        let remote_guard = InConnectionGuard {
            context: self.context.clone(),
            connection_ctx,
        };

        if self.context.check_client_blocked(src_addr) {
            return Ok(policy::StreamAction::ClientBlocked);
        }

        if self.context.check_outbound_blocked(target_addr).await {
            return Ok(policy::StreamAction::OutboundBlocked);
        }

        #[cfg(feature = "rate-limit")]
        let rate_limit = match self.context.connection_bound_width() {
            Some(bound_width) => Some(Arc::new(RateLimiter::new(Some(bound_width.clone()))?)),
            None => None,
        };

        cfg_if! {
            if #[cfg(feature = "server-mock")] {
                if let Some(protocol) = self.context.mock_server_protocol(target_addr) {
                    return Ok(policy::StreamAction::Local {
                        processor: Box::new(LocalProcessor::new(
                            self.context.clone(),
                            protocol,
                            remote_guard,
                            #[cfg(feature = "statistics")]
                            shadowsocks::statistics::ConnGuard::new_with_target(
                                bu_context,
                                shadowsocks::statistics::Target::Inapp(protocol.name()),
                                shadowsocks::statistics::METRIC_TCP_CONN_OUT,
                                Some(shadowsocks::statistics::METRIC_TCP_CONN_OUT_TOTAL),
                            ),
                        ))
                    });
                }
            }
        }

        Ok(StreamAction::Remote {
            connection_guard: Box::new(remote_guard) as Box<dyn policy::ConnectionGuard>,
            #[cfg(feature = "rate-limit")]
            rate_limit,
        })
    }

    async fn packet_check(
        &self,
        src_addr: Option<&SocketAddr>,
        target_addr: &ServerAddr,
    ) -> io::Result<policy::PacketAction> {
        // 后续支持不同地址的处理
        if let Some(src_addr) = src_addr {
            if self.context.check_client_blocked(src_addr) {
                return Ok(policy::PacketAction::ClientBlocked);
            }
        };

        if self.context.check_outbound_blocked(target_addr).await {
            return Ok(policy::PacketAction::OutboundBlocked);
        }

        Ok(policy::PacketAction::Remote)
    }
}

pub struct OutgoingUdpSocket {
    context: Arc<ServiceContext>,
    max_udp_packet_size: usize,
    outbound_ipv4_socket: spin::Mutex<Option<Arc<UdpSocket>>>,
    outbound_ipv6_socket: spin::Mutex<Option<Arc<UdpSocket>>>,
    socket_update_tx: Sender<()>,
    socket_update_rx: tokio::sync::Mutex<Receiver<()>>,
}

impl OutgoingUdpSocket {
    pub fn new(context: Arc<ServiceContext>, max_udp_packet_size: usize) -> Self {
        let (socket_update_tx, socket_update_rx) = tokio::sync::mpsc::channel(1);

        Self {
            context,
            max_udp_packet_size,
            outbound_ipv4_socket: spin::Mutex::new(None),
            outbound_ipv6_socket: spin::Mutex::new(None),
            socket_update_tx,
            socket_update_rx: tokio::sync::Mutex::new(socket_update_rx),
        }
    }

    async fn send_to_sock_addr(&self, mut target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        const UDP_SOCKET_SUPPORT_DUAL_STACK: bool = cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "freebsd",
            // target_os = "dragonfly",
            // target_os = "netbsd",
            target_os = "windows",
        ));

        let mut socket_updated = false;

        let socket = if UDP_SOCKET_SUPPORT_DUAL_STACK {
            let mut outbound_ipv6_socket = self.outbound_ipv6_socket.lock();
            match *outbound_ipv6_socket {
                Some(ref socket) => socket.clone(),
                None => {
                    let socket =
                        UdpSocket::connect_any_with_opts(AddrFamily::Ipv6, self.context.connect_opts_ref()).await?;

                    trace!("OUTGOING: socket ipv6 created",);

                    socket_updated = true;
                    outbound_ipv6_socket.insert(Arc::new(socket)).clone()
                }
            }
        } else {
            match target_addr {
                SocketAddr::V4(..) => {
                    let mut outbound_ipv4_socket = self.outbound_ipv4_socket.lock();
                    match *outbound_ipv4_socket {
                        Some(ref socket) => socket.clone(),
                        None => {
                            let socket =
                                UdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;

                            trace!("OUTGOING: socket ipv4 created");

                            socket_updated = true;
                            outbound_ipv4_socket.insert(Arc::new(socket)).clone()
                        }
                    }
                }
                SocketAddr::V6(..) => {
                    let mut outbound_ipv6_socket = self.outbound_ipv6_socket.lock();
                    match *outbound_ipv6_socket {
                        Some(ref socket) => socket.clone(),
                        None => {
                            let socket =
                                UdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;

                            trace!("OUTGOING: socket ipv6 created");

                            socket_updated = true;
                            outbound_ipv6_socket.insert(Arc::new(socket)).clone()
                        }
                    }
                }
            }
        };

        if socket_updated {
            self.socket_update_tx
                .send(())
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("notify reader sock update error {}", e)))?;
        }

        if UDP_SOCKET_SUPPORT_DUAL_STACK {
            if let SocketAddr::V4(saddr) = target_addr {
                let mapped_ip = saddr.ip().to_ipv6_mapped();
                target_addr = SocketAddr::V6(SocketAddrV6::new(mapped_ip, saddr.port(), 0, 0));
            }
        }

        match socket.send_to(data, target_addr).await {
            Err(err) => {
                error!(error = ?err, target = target_addr.to_string(), pkt.len = data.len(), "OUTGOING: --> send error");
                Err(err)
            }
            Ok(n) => {
                if n != data.len() {
                    error!(
                        target = target_addr.to_string(),
                        pkt.len = data.len(),
                        send.len = n,
                        "OUTGOING: --> send bytes mismatch"
                    );
                    Err(io::Error::new(io::ErrorKind::Other, "send size mismatched"))
                } else {
                    trace!(target = target_addr.to_string(), pkt.len = data.len(), "OUTGOING: --> ");
                    Ok(())
                }
            }
        }
    }
}

#[async_trait]
impl policy::UdpSocket for OutgoingUdpSocket {
    async fn recv_from(&self) -> io::Result<(Bytes, SocketAddr)> {
        #[inline]
        async fn receive_from_outbound_opt(
            socket: &Option<Arc<UdpSocket>>,
            max_udp_packet_size: usize,
        ) -> io::Result<(Bytes, SocketAddr)> {
            match *socket {
                None => unreachable!(),
                Some(ref s) => {
                    let mut buf = vec![0; max_udp_packet_size];
                    match s.recv_from(&mut buf).await {
                        Ok((len, addr)) => {
                            buf.truncate(len);

                            trace!(target = addr.to_string(), pkt.len = len, "OUTGOING: <-- ");

                            Ok((Bytes::from(buf), addr))
                        }
                        Err(err) => {
                            error!(
                                error = ?err,
                                "OUTGOING: <-- send error"
                            );
                            Err(err)
                        }
                    }
                }
            }
        }

        loop {
            let outbound_ipv4_socket = self.outbound_ipv4_socket.lock().clone();
            let outbound_ipv6_socket = self.outbound_ipv6_socket.lock().clone();
            let mut socket_update_rx = self.socket_update_rx.lock().await;

            tokio::select! {
                received_opt = receive_from_outbound_opt(&outbound_ipv4_socket, self.max_udp_packet_size)
                    , if outbound_ipv4_socket.is_some() => {
                        return received_opt;
                }
                received_opt = receive_from_outbound_opt(&outbound_ipv6_socket, self.max_udp_packet_size)
                    , if outbound_ipv6_socket.is_some() => {
                        return received_opt;
                }
                _socket_updated = socket_update_rx.recv() => {
                    trace!("OUTGOING: socket updated");
                }
            }
        }
    }

    async fn send_to(&self, buf: &[u8], addr: ServerAddr) -> io::Result<()> {
        match addr {
            ServerAddr::SocketAddr(sa) => self.send_to_sock_addr(sa, buf).await,
            ServerAddr::DomainName(ref dname, port) => lookup_then!(self.context.context_ref(), dname, port, |sa| {
                self.send_to_sock_addr(sa, buf).await
            })
            .map(|_| ()),
        }
    }
}

async fn timeout_fut<F, R>(duration: Duration, f: F) -> io::Result<R>
where
    F: Future<Output = io::Result<R>> + Send,
{
    match tokio::time::timeout(duration, f).await {
        Ok(o) => o,
        Err(..) => Err(io::ErrorKind::TimedOut.into()),
    }
}
