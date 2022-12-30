use bytes::Bytes;
use parking_lot::Mutex;
use std::fmt;
use std::time::Duration;
use std::{collections::HashMap, io::Error as IoError, net::SocketAddr, sync::Arc};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{debug, error, info_span, warn, Instrument, Span};

use crate::{
    canceler::Canceler,
    policy::{PacketAction, ServerPolicy, UdpSocket},
    timeout::{TimeoutTicker, TimeoutWaiter},
    ServerAddr,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum UdpSessionCloseReason {
    ClientClose,
    Shutdown,
    ChannelBroken,
    OutgoingSockError,
    IdleTimeout,
}

impl fmt::Debug for UdpSessionCloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientClose => write!(f, "client-close"),
            Self::Shutdown => write!(f, "shutdown"),
            Self::ChannelBroken => write!(f, "channel-broken"),
            Self::OutgoingSockError => write!(f, "outgoing-sock-error"),
            Self::IdleTimeout => write!(f, "idle-timeout"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum UdpSessionSource {
    Datagram,
    UniStream,
}

impl fmt::Debug for UdpSessionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Datagram => write!(f, "datagram"),
            Self::UniStream => write!(f, "uni-stream"),
        }
    }
}

pub type SessionCloseReceiver = Receiver<(u32, UdpSessionCloseReason)>;
pub type SessionCloseSender = Sender<(u32, UdpSessionCloseReason)>;

pub type SendPacketSender = Sender<(Bytes, ServerAddr, Span)>;
pub type SendPacketReceiver = Receiver<(Bytes, ServerAddr, Span)>;
pub type RecvPacketSender = Sender<(u32, Bytes, ServerAddr)>;
pub type RecvPacketReceiver = Receiver<(u32, Bytes, ServerAddr)>;

pub struct UdpSessionMap {
    map: Mutex<HashMap<u32, UdpSession>>,
    recv_pkt_tx_for_clone: RecvPacketSender,
    session_close_tx: SessionCloseSender,
    idle_timeout: Duration,
}

impl UdpSessionMap {
    pub fn new(idle_timeout: Duration) -> (Self, RecvPacketReceiver, SessionCloseReceiver) {
        let (session_close_tx, session_close_rx) = mpsc::channel(1);
        let (recv_pkt_tx, recv_pkt_rx) = mpsc::channel(1);

        (
            Self {
                map: Mutex::new(HashMap::new()),
                recv_pkt_tx_for_clone: recv_pkt_tx,
                session_close_tx,
                idle_timeout,
            },
            recv_pkt_rx,
            session_close_rx,
        )
    }

    #[allow(clippy::await_holding_lock)]
    pub async fn send_to_outgoing(
        &self,
        assoc_id: u32,
        source: UdpSessionSource,
        pkt: Bytes,
        addr: ServerAddr,
        src_addr: SocketAddr,
        server_policy: Arc<Box<dyn ServerPolicy>>,
        #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
    ) -> Result<usize, IoError> {
        let mut send_pkt_tx = self
            .map
            .lock()
            .get(&assoc_id)
            .map(|s| (s.packet_sender.clone(), s.span.clone()));

        if send_pkt_tx.is_none() {
            let assoc = UdpSession::new(
                assoc_id,
                source,
                self.recv_pkt_tx_for_clone.clone(),
                self.session_close_tx.clone(),
                server_policy.as_ref(),
                self.idle_timeout.clone(),
                #[cfg(feature = "statistics")]
                bu_context,
            )
            .instrument(info_span!("udp-session", id = assoc_id, source = format!("{:?}", source)).or_current())
            .await?;

            send_pkt_tx = Some((assoc.packet_sender.clone(), assoc.span.clone()));

            let mut map = self.map.lock();
            map.insert(assoc_id, assoc);
        }

        let (sender, span) = send_pkt_tx.unwrap();
        async move {
            let addr_for_log = addr.to_string();
            let len = pkt.len();

            match server_policy.packet_check(Some(&src_addr), &addr).await? {
                PacketAction::ClientBlocked => {
                    warn!(target = addr_for_log, "client blocked by ACL rules");
                    return Ok(0);
                }
                PacketAction::OutboundBlocked => {
                    warn!(target = addr_for_log, "outbound blocked by ACL rules");
                    return Ok(0);
                }
                PacketAction::Remote => match sender.send((pkt, addr, Span::current())).await {
                    Ok(()) => Ok(len),
                    Err(err) => {
                        debug!(target = addr_for_log, error = ?err, "send channel closed");
                        self.dissociate(assoc_id, UdpSessionCloseReason::ChannelBroken).await;
                        Ok(0)
                    }
                },
            }
        }
        .instrument(span)
        .await
    }

    pub fn find_session(&self, assoc_id: u32) -> Option<(UdpSessionSource, Span)> {
        self.map
            .lock()
            .get(&assoc_id)
            .map(|s| (s.source.clone(), s.span.clone()))
    }

    pub fn session_ids(&self) -> Vec<u32> {
        self.map.lock().keys().copied().collect()
    }

    pub async fn dissociate(&self, assoc_id: u32, reason: UdpSessionCloseReason) -> bool {
        let session = self.map.lock().remove(&assoc_id);
        if let Some(session) = session {
            session.close(reason).await;
            return true;
        } else {
            return false;
        }
    }
}

struct UdpSession {
    source: UdpSessionSource,
    packet_sender: SendPacketSender,
    span: Span,
    canceler: Canceler,
    task: tokio::task::JoinHandle<()>,
    #[cfg(feature = "statistics")]
    _in_conn_guard: crate::statistics::ConnGuard,
}

impl UdpSession {
    async fn new(
        assoc_id: u32,
        source: UdpSessionSource,
        recv_pkt_tx: RecvPacketSender,
        session_close_tx: SessionCloseSender,
        server_policy: &Box<dyn ServerPolicy>,
        idle_timeout: Duration,
        #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
    ) -> Result<Self, IoError> {
        let socket = Arc::new(server_policy.create_out_udp_socket().await?);
        let (send_pkt_tx, send_pkt_rx) = mpsc::channel(1);
        let canceler = Canceler::new();

        let waiter = canceler.waiter();
        let task = tokio::spawn(
            async move {
                let timeout_waiter = TimeoutWaiter::new(idle_timeout);
                let timeout_ticker_1 = timeout_waiter.ticker();
                let timeout_ticker_2 = timeout_waiter.ticker();
                tokio::pin!(timeout_waiter);
                let close_reason = tokio::select!(
                    r = Self::listen_send_packet(socket.clone(), send_pkt_rx, timeout_ticker_1) => r,
                    r = Self::listen_receive_packet(socket, assoc_id, recv_pkt_tx, timeout_ticker_2) => r,
                    _ = &mut timeout_waiter => UdpSessionCloseReason::IdleTimeout,
                    _ = waiter.wait() => { return; }
                );

                if let Err(err) = session_close_tx.send((assoc_id, close_reason)).await {
                    error!(error = ?err, reason = ?close_reason, "notify close session fail");
                }
            }
            .in_current_span(),
        );

        debug!("created");
        Ok(Self {
            source,
            packet_sender: send_pkt_tx,
            span: Span::current(),
            canceler,
            task,
            #[cfg(feature = "statistics")]
            _in_conn_guard: crate::statistics::ConnGuard::new(
                bu_context,
                crate::statistics::METRIC_UDP_SESSION,
                Some(crate::statistics::METRIC_UDP_SESSION_TOTAL),
            ),
        })
    }

    async fn close(self, reason: UdpSessionCloseReason) {
        let UdpSession {
            span, task, canceler, ..
        } = self;

        async move {
            canceler.cancel();
            let _ = task.await;
            debug!(reason = ?reason, "closed");
        }
        .instrument(span)
        .await
    }

    async fn listen_send_packet(
        socket: Arc<Box<dyn UdpSocket>>,
        mut send_pkt_rx: SendPacketReceiver,
        timeout_ticker: TimeoutTicker,
    ) -> UdpSessionCloseReason {
        while let Some((pkt, addr, span)) = send_pkt_rx.recv().await {
            match socket.send_to(&pkt, addr).instrument(span).await {
                Ok(()) => timeout_ticker.tick(),
                Err(_err) => {
                    return UdpSessionCloseReason::OutgoingSockError;
                }
            }
        }

        return UdpSessionCloseReason::ChannelBroken;
    }

    async fn listen_receive_packet(
        socket: Arc<Box<dyn UdpSocket>>,
        assoc_id: u32,
        recv_pkt_tx: RecvPacketSender,
        timeout_ticker: TimeoutTicker,
    ) -> UdpSessionCloseReason {
        loop {
            let (pkt, addr) = match socket.recv_from().await {
                Ok(r) => {
                    timeout_ticker.tick();
                    r
                }
                Err(err) => {
                    error!(error = ?err, "outgoing socket recv error");
                    return UdpSessionCloseReason::OutgoingSockError;
                }
            };

            match recv_pkt_tx.send((assoc_id, pkt, ServerAddr::SocketAddr(addr))).await {
                Ok(()) => {}
                Err(err) => {
                    error!(error = ?err, "tuic udp send back channel closed");
                    return UdpSessionCloseReason::ChannelBroken;
                }
            };
        }
    }
}
