//! UDP Association Managing

use std::{
    cell::RefCell,
    collections::HashMap,
    fmt, io,
    marker::PhantomData,
    net::{SocketAddr, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use futures::future;
use lru_time_cache::LruCache;
use rand::{rngs::SmallRng, Rng, SeedableRng};
use tokio::{sync::mpsc, task::JoinHandle, time};
use tracing::{debug, error, info_span, trace, warn, Instrument, Span};

use shadowsocks::{
    config::ServerProtocol,
    lookup_then,
    net::{AddrFamily, UdpSocket as ShadowUdpSocket},
    relay::{
        udprelay::{options::UdpSocketControlData, ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
        Address,
    },
    timeout::TimeoutWaiter,
    transport::StreamConnection,
    ServerAddr, ServerConfig,
};

use crate::{
    local::{context::ServiceContext, loadbalancing::PingBalancer},
    net::{packet_window::PacketWindowFilter, UDP_ASSOCIATION_CLOSE_CHANNEL_SIZE, UDP_ASSOCIATION_SEND_CHANNEL_SIZE},
};

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "sniffer")] {
        use crate::sniffer::{SnifferChainHead, SnifferCheckError, SnifferChain};
        use crate::local::context::ProtocolAction;
    }
}

cfg_if! {
    if #[cfg(feature = "sniffer-bittorrent")] {
        use crate::sniffer::SnifferUtp;
    }
}

cfg_if! {
    if #[cfg(feature = "rate-limit")] {
        use nonzero_ext::*;
        use shadowsocks::transport::{NegativeMultiDecision};
    }
}

/// Writer for sending packets back to client
///
/// Currently it requires `async-trait` for `async fn` in trait, which will allocate a `Box`ed `Future` every call of `send_to`.
/// This performance issue could be solved when `generic_associated_types` and `generic_associated_types` are stabilized.
#[async_trait]
pub trait UdpInboundWrite {
    /// Sends packet `data` received from `remote_addr` back to `peer_addr`
    async fn send_to(&self, peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()>;
}

#[derive(Debug)]
pub enum UdpAssociationCloseReason {
    RemoteSocketError,
    LocalSocketError,
    FakeClose,
    IdleTimeout,
    InternalError,
}

impl fmt::Display for UdpAssociationCloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteSocketError => write!(f, "remote-sock-error"),
            Self::LocalSocketError => write!(f, "local-sock-error"),
            Self::FakeClose => write!(f, "fake-close"),
            Self::IdleTimeout => write!(f, "idle-timeout"),
            Self::InternalError => write!(f, "internal-error"),
        }
    }
}

pub type UdpAssociationCloseReceiver = mpsc::Receiver<(SocketAddr, UdpAssociationCloseReason)>;
type UdpAssociationCloseSender = mpsc::Sender<(SocketAddr, UdpAssociationCloseReason)>;

type AssociationMap<W> = HashMap<SocketAddr, UdpAssociation<W>>;

/// UDP association manager
pub struct UdpAssociationManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    respond_writer: W,
    context: Arc<ServiceContext>,
    assoc_map: AssociationMap<W>,
    close_tx: UdpAssociationCloseSender,
    balancer: PingBalancer,
    server_session_expire_duration: Duration,
}

impl<W> UdpAssociationManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    /// Create a new `UdpAssociationManager`
    ///
    /// Returns (`UdpAssociationManager`, Cleanup Interval, Keep-alive Receiver<SocketAddr>)
    pub fn new(
        context: Arc<ServiceContext>,
        respond_writer: W,
        time_to_live: Option<Duration>,
        _capacity: Option<usize>,
        balancer: PingBalancer,
    ) -> (UdpAssociationManager<W>, UdpAssociationCloseReceiver) {
        let time_to_live = time_to_live.unwrap_or(crate::DEFAULT_UDP_EXPIRY_DURATION);
        let assoc_map = AssociationMap::new();

        let (close_tx, close_rx) = mpsc::channel(UDP_ASSOCIATION_CLOSE_CHANNEL_SIZE);

        (
            UdpAssociationManager {
                respond_writer,
                context,
                assoc_map,
                close_tx,
                balancer,
                server_session_expire_duration: time_to_live,
            },
            close_rx,
        )
    }

    /// Sends `data` from `peer_addr` to `target_addr`
    pub async fn send_to(&mut self, peer_addr: SocketAddr, target_addr: Address, data: &[u8]) -> io::Result<()> {
        // Check or (re)create an association

        let mut assoc = self.assoc_map.get(&peer_addr);
        let mut is_new = false;

        if assoc.is_none() {
            let new_assoc = UdpAssociation::new(
                self.context.clone(),
                peer_addr,
                self.close_tx.clone(),
                self.balancer.clone(),
                self.respond_writer.clone(),
                self.server_session_expire_duration,
            );
            self.assoc_map.insert(peer_addr, new_assoc);

            assoc = self.assoc_map.get(&peer_addr);
            is_new = true;
        }

        let assoc = assoc.unwrap();
        let _enter = assoc.span.clone().entered();
        if is_new {
            debug!("udp association created");
        }

        let span = info_span!("udp.local", target = target_addr.to_string());
        let _enter = span.enter();

        cfg_if! {
            if #[cfg(all(feature = "sniffer-bittorrent"))] {

                #[allow(unused_mut)]
                let mut sniffer = SnifferChainHead::new();

                #[cfg(feature = "sniffer-bittorrent")]
                #[allow(unused_mut)]
                let mut sniffer = sniffer.join(SnifferUtp::new());

                let protocol = match sniffer.check(data) {
                    Ok(protocol) => Some(protocol),
                    Err(SnifferCheckError::NoClue) => None,
                    Err(SnifferCheckError::Reject) => None,
                    Err(SnifferCheckError::Other(err)) => {
                        error!(error = ?err, "sniffer package for error");
                        return Err(io::Error::new(io::ErrorKind::Other, err));
                    }
                };

                let action = self.context.protocol_action(&protocol);
                if let Some(action) = action {
                    match action {
                        ProtocolAction::Reject => {
                            trace!(protocol = format!("{:?}", protocol.unwrap()), "reject");
                            return Ok(());
                        }
                    }
                }
            }
        }

        if let Err(err) = assoc
            .sender
            .try_send((target_addr, Bytes::copy_from_slice(data), span.clone()))
        {
            debug!(error = ?err, "send to context fail");
        }

        Ok(())
    }

    /// close association
    pub fn close_association(&mut self, peer_addr: &SocketAddr, reason: UdpAssociationCloseReason) {
        if let Some(association) = self.assoc_map.remove(peer_addr) {
            let _enter = association.span.enter();
            debug!(reason = reason.to_string(), "closed");
        }
    }
}

struct UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    assoc_handle: JoinHandle<()>,
    sender: mpsc::Sender<(Address, Bytes, Span)>,
    writer: PhantomData<W>,
    span: Span,
}

impl<W> Drop for UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn drop(&mut self) {
        self.assoc_handle.abort();
    }
}

impl<W> UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn new(
        context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        close_tx: UdpAssociationCloseSender,
        balancer: PingBalancer,
        respond_writer: W,
        server_session_expire_duration: Duration,
    ) -> UdpAssociation<W> {
        let span = info_span!("udp-session", peer.addr = peer_addr.to_string());
        let (assoc_handle, sender) = UdpAssociationContext::create(
            context,
            peer_addr,
            close_tx,
            balancer,
            respond_writer,
            server_session_expire_duration,
            span.clone(),
        );
        UdpAssociation {
            assoc_handle,
            sender,
            writer: PhantomData,
            span,
        }
    }
}

#[derive(Debug, Clone)]
struct ServerContext {
    packet_window_filter: PacketWindowFilter,
}

#[derive(Clone)]
struct ServerSessionContext {
    server_session_map: LruCache<u64, ServerContext>,
}

impl ServerSessionContext {
    fn new(session_expire_duration: Duration) -> ServerSessionContext {
        ServerSessionContext {
            server_session_map: LruCache::with_expiry_duration(session_expire_duration),
        }
    }
}

enum MultiProtocolProxySocket {
    SS(ProxySocket),
    #[cfg(feature = "trojan")]
    Trojan(trojan::TrojanUdpContext),
    #[cfg(feature = "vless")]
    Vless(vless::VlessUdpContext),
    #[cfg(feature = "tuic")]
    Tuic(tuic::TuicUdpContext),
}

struct UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    bypassed_ipv4_socket: Option<ShadowUdpSocket>,
    bypassed_ipv6_socket: Option<ShadowUdpSocket>,
    proxied_socket: Option<MultiProtocolProxySocket>,
    close_tx: UdpAssociationCloseSender,
    balancer: PingBalancer,
    respond_writer: W,
    client_session_id: u64,
    client_packet_id: u64,
    server_session: Option<ServerSessionContext>,
    server_session_expire_duration: Duration,
    span: Span,
}

impl<W> Drop for UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn drop(&mut self) {
        let _enter = self.span.enter();
        trace!("udp association destoried");
    }
}

thread_local! {
    static CLIENT_SESSION_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_entropy());
}

#[inline]
fn generate_client_session_id() -> u64 {
    CLIENT_SESSION_RNG.with(|rng| rng.borrow_mut().gen())
}

impl<W> UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn create(
        context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        close_tx: UdpAssociationCloseSender,
        balancer: PingBalancer,
        respond_writer: W,
        server_session_expire_duration: Duration,
        span: Span,
    ) -> (JoinHandle<()>, mpsc::Sender<(Address, Bytes, Span)>) {
        // Pending packets UDP_ASSOCIATION_SEND_CHANNEL_SIZE for each association should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_CHANNEL_SIZE);

        let assoc = UdpAssociationContext {
            context,
            peer_addr,
            bypassed_ipv4_socket: None,
            bypassed_ipv6_socket: None,
            proxied_socket: None,
            close_tx,
            balancer,
            respond_writer,
            // client_session_id must be random generated,
            // server use this ID to identify every independent clients.
            client_session_id: generate_client_session_id(),
            client_packet_id: 0,
            server_session: None,
            server_session_expire_duration,
            span: span.clone(),
        };
        let handle = tokio::spawn(assoc.dispatch_packet(receiver).instrument(span));

        (handle, sender)
    }

    #[cfg(not(feature = "rate-limit"))]
    #[inline]
    fn check_rate_limit(&self, processed_size: &mut usize) -> Option<time::Duration> {
        *processed_size = 0;
        None
    }

    #[cfg(feature = "rate-limit")]
    #[inline]
    fn check_rate_limit(&self, processed_size: &mut usize) -> Option<time::Duration> {
        if *processed_size == 0 {
            return None;
        }

        let limiter = self.context.rate_limiter();

        let check_n = |processed_size: usize| {
            match limiter.check_n((processed_size as u32).into_nonzero().unwrap()) {
                Err(err) => match err {
                    NegativeMultiDecision::BatchNonConforming(duration) => Some(duration),
                    NegativeMultiDecision::InsufficientCapacity => {
                        // 读入的数据超过了最大读取数据，在读取时已经保护过，不应该再进入这个情况
                        tracing::error!("xxxxx: check_n size={} unexpected", processed_size);
                        unreachable!()
                    }
                },
                Ok(..) => None,
            }
        };

        let mut duration = None;
        if let Some(max_once_size) = limiter.max_receive_once() {
            assert!(max_once_size > 0);

            while *processed_size > 0 {
                let check_size = std::cmp::min(*processed_size, max_once_size);
                duration = check_n(check_size);

                if duration.is_some() {
                    break;
                }

                *processed_size -= check_size;
            }
        } else {
            duration = check_n(*processed_size);
            if duration.is_none() {
                *processed_size = 0;
            }
        }

        assert!((duration.is_some() && *processed_size > 0) || duration.is_none() && *processed_size == 0);

        // if duration.is_some() {
        //     tracing::error!(
        //         "xxxxx: rate-limit sleep begin: size={}, duration={:?}",
        //         *processed_size,
        //         duration.unwrap()
        //     );
        // } else {
        //     tracing::error!("xxxxx: rate-limit sleep end");
        // }

        duration
    }

    #[inline]
    async fn wait_rate_limit_complete(duration: Option<time::Duration>) {
        match duration {
            Some(duration) => time::sleep(duration).await,
            None => future::pending().await,
        }
    }

    async fn dispatch_packet(mut self, mut receiver: mpsc::Receiver<(Address, Bytes, Span)>) {
        let mut bypassed_ipv4_buffer = Vec::new();
        let mut bypassed_ipv6_buffer = Vec::new();
        let mut proxied_buffer = Vec::new();
        let close_notify = self.context.connection_close_notify();
        let flow_state = self.context.flow_stat();

        let mut check_rate_limit_size: usize = 0;
        let idle_timeout = TimeoutWaiter::new(self.server_session_expire_duration);

        tokio::pin!(idle_timeout);

        let close_reason = loop {
            let rate_limit_duration = self.check_rate_limit(&mut check_rate_limit_size);
            assert!(
                (rate_limit_duration.is_some() && check_rate_limit_size > 0)
                    || (rate_limit_duration.is_none() && check_rate_limit_size == 0)
            );

            tokio::select! {
                _ = Self::wait_rate_limit_complete(rate_limit_duration), if check_rate_limit_size> 0 => {
                }

                packet_received_opt = receiver.recv() => {
                    let (target_addr, data, span) = match packet_received_opt {
                        Some(d) => d,
                        None => {
                            debug!("receive channel closed");
                            break UdpAssociationCloseReason::InternalError;
                        }
                    };

                    if let Err(close_reason) = self.dispatch_received_packet(&target_addr, &data, &mut check_rate_limit_size).instrument(span).await {
                        break close_reason;
                    }
                }

                received_opt = Self::receive_from_bypassed_opt(&self.bypassed_ipv4_socket, &mut bypassed_ipv4_buffer), if self.bypassed_ipv4_socket.is_some() => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!(error = ?err, "receive from bypassed(ipv4) fail");
                            // Socket failure. Reset for recreation.
                            self.bypassed_ipv4_socket = None;
                            continue;
                        }
                    };

                    let span = info_span!("udp.remote", target = addr.to_string(), source = "bypass");
                    let addr = Address::from(addr);
                    if let Err(close_reason) = self.send_received_respond_packet(&addr, &bypassed_ipv4_buffer[..n], true, &mut check_rate_limit_size).instrument(span).await {
                        break close_reason;
                    }
                }

                received_opt = Self::receive_from_bypassed_opt(&self.bypassed_ipv6_socket, &mut bypassed_ipv6_buffer), if self.bypassed_ipv6_socket.is_some() => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!(error = ?err, "receive from bypassed(ipv6) fail");
                            // Socket failure. Reset for recreation.
                            self.bypassed_ipv6_socket = None;
                            continue;
                        }
                    };

                    let span = info_span!("udp.remote", target = addr.to_string(), source = "bypass");
                    let addr = Address::from(addr);
                    if let Err(close_reason) = self.send_received_respond_packet(&addr, &bypassed_ipv6_buffer[..n], true, &mut check_rate_limit_size).instrument(span).await {
                        break close_reason;
                    }
                }

                received_opt = Self::receive_from_proxied_opt(&mut self.proxied_socket, &mut proxied_buffer), if check_rate_limit_size == 0 && self.proxied_socket.is_some() => {
                    let (n, addr, control_opt) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!(error = ?err, "receive from proxied failed");
                            // Socket failure. Reset for recreation.
                            self.proxied_socket = None;
                            continue;
                        }
                    };

                    let span = info_span!("udp.remote", target = addr.to_string(), source = "proxied");
                    let _enter = span.enter();

                    flow_state.incr_rx(n as u64);

                    if let Some(control) = control_opt {
                        // Check if Packet ID is in the window

                        let session = self.server_session.get_or_insert_with(|| {
                            ServerSessionContext::new(self.server_session_expire_duration)
                        });

                        let packet_id = control.packet_id;
                        let session_context = session
                            .server_session_map
                            .entry(control.server_session_id)
                            .or_insert_with(|| {
                                trace!(
                                    "udp server with session {} created",
                                    control.client_session_id,
                                );

                                ServerContext {
                                    packet_window_filter: PacketWindowFilter::new()
                                }
                            });

                        if !session_context.packet_window_filter.validate_packet_id(packet_id, u64::MAX) {
                            error!("packet_id {} out of window", packet_id);
                            continue;
                        }
                    }

                    idle_timeout.tick();
                    if let Err(close_reason) = self.send_received_respond_packet(&addr, &proxied_buffer[..n], false, &mut check_rate_limit_size).instrument(span.clone()).await {
                        break close_reason;
                    }
                }

                _ = close_notify.notified() => {
                    trace!("fake closed");
                    break UdpAssociationCloseReason::FakeClose;
                }

                _ = &mut idle_timeout => {
                    trace!("idle timeout");
                    break UdpAssociationCloseReason::IdleTimeout;
                }
            }
        };

        match self.close_tx.send((self.peer_addr, close_reason)).await {
            Ok(()) => {
                // 发送关闭消息以后，等待被删除，但是为了防止泄漏，此处用 sleep(1) 等待
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(err) => {
                error!(error = ?err, "send close reason fail");
            }
        }
    }

    #[inline]
    async fn receive_from_bypassed_opt(
        socket: &Option<ShadowUdpSocket>,
        buf: &mut Vec<u8>,
    ) -> io::Result<(usize, SocketAddr)> {
        match *socket {
            None => future::pending().await,
            Some(ref s) => {
                if buf.is_empty() {
                    buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
                }
                s.recv_from(buf).await
            }
        }
    }

    #[inline]
    async fn receive_from_proxied_opt(
        socket: &mut Option<MultiProtocolProxySocket>,
        buf: &mut Vec<u8>,
    ) -> Result<(usize, Address, Option<UdpSocketControlData>), UdpAssociationCloseReason> {
        match socket {
            None => future::pending().await,
            Some(ref mut socket) => {
                if buf.is_empty() {
                    buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
                }

                match socket {
                    MultiProtocolProxySocket::SS(ref s) => match s.recv_with_ctrl(buf).await {
                        Ok((size, addr, _recv_size, control_data)) => Ok((size, Address::from(addr), control_data)),
                        Err(err) => {
                            error!(error = ?err, "ss socket recv error");
                            Err(UdpAssociationCloseReason::RemoteSocketError)
                        }
                    },
                    #[cfg(feature = "trojan")]
                    MultiProtocolProxySocket::Trojan(ref mut context) => context.trojan_receive_from(buf).await,
                    #[cfg(feature = "vless")]
                    MultiProtocolProxySocket::Vless(ref mut context) => context.vless_receive_from(buf).await,
                    #[cfg(feature = "tuic")]
                    MultiProtocolProxySocket::Tuic(ref mut context) => context.tuic_receive_from(buf).await,
                }
            }
        }
    }

    async fn dispatch_received_packet(
        &mut self,
        target_addr: &Address,
        data: &[u8],
        check_rate_limit_size: &mut usize,
    ) -> Result<(), UdpAssociationCloseReason> {
        // Check if target should be bypassed. If so, send packets directly.
        #[allow(unused_mut)]
        let mut bypassed = self.balancer.is_empty() || self.context.check_target_bypassed(target_addr).await;

        #[cfg(feature = "local-fake-mode")]
        if !bypassed {
            bypassed = self.context.fake_mode().is_bypass();
        }

        if bypassed {
            let _sended = self.dispatch_received_bypassed_packet(target_addr, data).await;
        } else if *check_rate_limit_size > 0 {
            debug!(
                target = target_addr.to_string(),
                pkt.len = data.len(),
                "==> discard for rate-limited"
            );
        } else {
            let sended = self.dispatch_received_proxied_packet(target_addr, data).await?;
            if sended {
                *check_rate_limit_size += data.len();
            }
        }
        Ok(())
    }

    async fn dispatch_received_bypassed_packet(&mut self, target_addr: &Address, data: &[u8]) -> bool {
        match *target_addr {
            Address::SocketAddress(sa) => self.send_received_bypassed_packet(sa, data).await,
            Address::DomainNameAddress(ref dname, port) => {
                match self
                    .dispatch_received_bypassed_packet_domain_name(dname, port, data)
                    .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        error!(error = ?err, target = target_addr.to_string(), pkt.len = data.len(), "==> dns resolve error");
                        false
                    }
                }
            }
        }
    }

    #[inline]
    async fn dispatch_received_bypassed_packet_domain_name(
        &mut self,
        target_dname: &str,
        target_port: u16,
        data: &[u8],
    ) -> io::Result<bool> {
        lookup_then!(self.context.context_ref(), target_dname, target_port, |sa| {
            io::Result::Ok(self.send_received_bypassed_packet(sa, data).await)
        })
        .map(|(_, r)| r)
    }

    async fn send_received_bypassed_packet(&mut self, mut target_addr: SocketAddr, data: &[u8]) -> bool {
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

        let socket = if UDP_SOCKET_SUPPORT_DUAL_STACK {
            match self.bypassed_ipv6_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket = match ShadowUdpSocket::connect_any_with_opts(
                        AddrFamily::Ipv6,
                        self.context.connect_opts_ref(),
                    )
                    .await
                    {
                        Ok(socket) => socket,
                        Err(err) => {
                            error!(error = ?err, opts = ?self.context.connect_opts_ref(), "create bypass ipv6 socket error(dual stack)");
                            return false;
                        }
                    };
                    self.bypassed_ipv6_socket.insert(socket)
                }
            }
        } else {
            match target_addr {
                SocketAddr::V4(..) => match self.bypassed_ipv4_socket {
                    Some(ref mut socket) => socket,
                    None => {
                        let socket = match ShadowUdpSocket::connect_any_with_opts(
                            &target_addr,
                            self.context.connect_opts_ref(),
                        )
                        .await
                        {
                            Ok(socket) => socket,
                            Err(err) => {
                                error!(error = ?err, opts = ?self.context.connect_opts_ref(), "create bypass ipv4 socket error");
                                return false;
                            }
                        };
                        self.bypassed_ipv4_socket.insert(socket)
                    }
                },
                SocketAddr::V6(..) => match self.bypassed_ipv6_socket {
                    Some(ref mut socket) => socket,
                    None => {
                        let socket = match ShadowUdpSocket::connect_any_with_opts(
                            &target_addr,
                            self.context.connect_opts_ref(),
                        )
                        .await
                        {
                            Ok(socket) => socket,
                            Err(err) => {
                                error!(error = ?err, opts = ?self.context.connect_opts_ref(), "create bypass ipv6 socket error");
                                return false;
                            }
                        };
                        self.bypassed_ipv6_socket.insert(socket)
                    }
                },
            }
        };

        if UDP_SOCKET_SUPPORT_DUAL_STACK {
            if let SocketAddr::V4(saddr) = target_addr {
                let mapped_ip = saddr.ip().to_ipv6_mapped();
                target_addr = SocketAddr::V6(SocketAddrV6::new(mapped_ip, saddr.port(), 0, 0));
            }
        }

        match socket.send_to(data, target_addr).await {
            Ok(n) => {
                if n != data.len() {
                    warn!("==> {} bytes send mismatched, expected={}", n, data.len());
                } else {
                    trace!(pkt.len = data.len(), "==> send success");
                }
                true
            }
            Err(err) => {
                error!(error = ?err, pkt.len = data.len(), "send bypass data error");
                false
            }
        }
    }

    async fn dispatch_received_proxied_packet(
        &mut self,
        target_addr: &Address,
        data: &[u8],
    ) -> Result<bool, UdpAssociationCloseReason> {
        // Increase Packet ID before send
        self.client_packet_id = match self.client_packet_id.checked_add(1) {
            Some(i) => i,
            None => {
                // FIXME: client_packet_id overflowed. What's the proper way to handle this?
                //
                // Reopen a new session is not perfect, because the remote target will receive packets from a different address.
                // For most application protocol, like QUIC, it is fine to change client address.
                //
                // But it will happen only when a client continously send 18446744073709551616 packets without renewing the socket.

                let new_session_id = generate_client_session_id();
                warn!(
                    "packet id overflowed. socket reset and session renewed ({} -> {})",
                    self.client_session_id, new_session_id
                );

                self.proxied_socket.take();
                self.client_packet_id = 1;
                self.client_session_id = new_session_id;

                self.client_packet_id
            }
        };

        let socket = match self.proxied_socket {
            Some(ref mut socket) => socket,
            None => {
                // Create a new connection to proxy server

                let server = self.balancer.best_udp_server();
                let svr_cfg = server.server_config();

                match svr_cfg.protocol() {
                    ServerProtocol::SS(svr_ss_cfg) => {
                        #[cfg(feature = "local-fake-mode")]
                        let mut _ss_cfg_buf = None;

                        #[allow(unused_mut)]
                        let mut effect_ss_cfg = svr_ss_cfg;

                        #[cfg(feature = "local-fake-mode")]
                        {
                            let fake_mode = self.context.fake_mode();
                            if let Some(fake_cfg) = fake_mode.is_param_error_for_ss(svr_ss_cfg) {
                                _ss_cfg_buf = Some(fake_cfg);
                                effect_ss_cfg = _ss_cfg_buf.as_ref().unwrap();
                            }
                        }

                        let socket = match ProxySocket::connect_with_opts(
                            self.context.context(),
                            svr_cfg,
                            effect_ss_cfg,
                            self.context.connect_opts_ref(),
                        )
                        .await
                        {
                            Ok(socket) => socket,
                            Err(err) => {
                                error!(error = ?err, "create ss socket error");
                                return Ok(false);
                            }
                        };

                        self.proxied_socket.insert(MultiProtocolProxySocket::SS(socket))
                    }
                    #[cfg(feature = "trojan")]
                    ServerProtocol::Trojan(svr_trojan_cfg) => {
                        #[cfg(feature = "local-fake-mode")]
                        let mut _trojan_cfg_buf = None;

                        #[allow(unused_mut)]
                        let mut effect_trojan_cfg = svr_trojan_cfg;

                        #[cfg(feature = "local-fake-mode")]
                        {
                            let fake_mode = self.context.fake_mode();
                            if let Some(fake_cfg) = fake_mode.is_param_error_for_trojan(svr_trojan_cfg) {
                                _trojan_cfg_buf = Some(fake_cfg);
                                effect_trojan_cfg = _trojan_cfg_buf.as_ref().unwrap();
                            }
                        }

                        let context = match self
                            .trojan_create_context(svr_cfg, effect_trojan_cfg, self.peer_addr, self.close_tx.clone())
                            .await
                        {
                            Ok(context) => context,
                            Err(_err) => {
                                return Ok(false);
                            }
                        };

                        self.proxied_socket.insert(context)
                    }
                    #[cfg(feature = "vless")]
                    ServerProtocol::Vless(..) => {
                        let context = match self
                            .vless_create_context(
                                self.context.clone(),
                                server.clone(),
                                self.server_session_expire_duration,
                            )
                            .await
                        {
                            Ok(context) => context,
                            Err(_err) => {
                                return Ok(false);
                            }
                        };
                        self.proxied_socket.insert(context)
                    }
                    #[cfg(feature = "tuic")]
                    ServerProtocol::Tuic(tuic_config) => {
                        let context = match self
                            .tuic_create_context(
                                server.as_ref(),
                                Some(self.context.connection_close_notify()),
                                tuic_config,
                            )
                            .await
                        {
                            Ok(context) => context,
                            Err(_err) => {
                                return Ok(false);
                            }
                        };
                        self.proxied_socket.insert(context)
                    }
                }
            }
        };

        // 多协议分支处理，这个结构是为了最大限度保留原有代码结构，方便合并
        let socket = match socket {
            MultiProtocolProxySocket::SS(socket) => socket,
            #[cfg(feature = "trojan")]
            MultiProtocolProxySocket::Trojan(ref mut context) => {
                let sended = context.trojan_try_send_to(target_addr, data)?;
                if sended {
                    self.context.flow_stat().incr_tx(data.len() as u64);
                }
                return Ok(sended);
            }
            #[cfg(feature = "vless")]
            MultiProtocolProxySocket::Vless(ref mut context) => {
                match context.vless_send_to(&self.peer_addr, target_addr, data).await {
                    Ok(()) => {
                        self.context.flow_stat().incr_tx(data.len() as u64);
                        return Ok(true);
                    }
                    Err(_err) => {
                        return Ok(false);
                    }
                }
            }
            #[cfg(feature = "tuic")]
            MultiProtocolProxySocket::Tuic(ref mut context) => {
                let sended = context.tuic_try_send_to(target_addr, data)?;
                if sended {
                    self.context.flow_stat().incr_tx(data.len() as u64);
                }
                return Ok(sended);
            }
        };

        // Increase Packet ID before send
        self.client_packet_id = match self.client_packet_id.checked_add(1) {
            Some(i) => i,
            None => {
                warn!(
                    error = "packet id overflowed",
                    target = target_addr.to_string(),
                    pkt.len = data.len(),
                    "==> sending failed"
                );
                return Ok(false);
            }
        };

        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client_session_id;
        control.packet_id = self.client_packet_id;

        match socket
            .send_with_ctrl(&ServerAddr::from(target_addr), &control, data)
            .await
        {
            Ok(..) => {
                self.context.flow_stat().incr_tx(data.len() as u64);
                Ok(true)
            }
            Err(err) => {
                debug!(error = ?err, target = target_addr.to_string(), pkt.len = data.len(), "==> sending fail");
                // Drop the socket and reconnect to another server.
                self.proxied_socket = None;
                Ok(false)
            }
        }
    }

    async fn send_received_respond_packet(
        &mut self,
        addr: &Address,
        data: &[u8],
        bypassed: bool,
        check_rate_limit_size: &mut usize,
    ) -> Result<(), UdpAssociationCloseReason> {
        // Send back to client
        if let Err(err) = self.respond_writer.send_to(self.peer_addr, addr, data).await {
            warn!(error = ?err, target = addr.to_string(), pkt.len = data.len(), "<== send error");
            Err(UdpAssociationCloseReason::LocalSocketError)
        } else {
            trace!(target = addr.to_string(), pkt.len = data.len(), "<== send success");
            if !bypassed {
                *check_rate_limit_size += data.len();
            }
            Ok(())
        }
    }
}

#[cfg(feature = "trojan")]
mod trojan;

#[cfg(feature = "vless")]
mod vless;

#[cfg(feature = "tuic")]
mod tuic;
