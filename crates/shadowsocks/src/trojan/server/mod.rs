use std::fmt;
use std::net::SocketAddr;
use std::{io, sync::Arc};
use tokio::time::{self, Duration};
use tracing::{debug, error, info_span, Instrument};

use crate::{
    canceler::CancelWaiter,
    policy::ServerPolicy,
    transport::{Acceptor, StreamConnection},
    ServerAddr,
};

mod stream;
mod udp;

use super::{protocol::RequestHeader, Config};

#[derive(Clone, Copy, Eq, PartialEq)]
enum CloseReason {
    ClientBlocked,
    OutboundBlocked,
    SockError,
    SockClosed,
    Canceled,
    IdleTimeout,
    RequestTimeout,
    InternalError,
}

impl fmt::Debug for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SockError => write!(f, "sock-error"),
            Self::SockClosed => write!(f, "sock-closed"),
            Self::ClientBlocked => write!(f, "client-blocked"),
            Self::OutboundBlocked => write!(f, "outgoing-blocked"),
            Self::Canceled => write!(f, "canceled"),
            Self::IdleTimeout => write!(f, "idle-timeout"),
            Self::RequestTimeout => write!(f, "request-timeout"),
            Self::InternalError => write!(f, "internal"),
        }
    }
}

pub async fn serve(
    mut listener: impl Acceptor + 'static,
    cancel_waiter: CancelWaiter,
    config: &Config,
    request_recv_timeout: Duration,
    idle_timeout: Duration,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
) -> io::Result<()> {
    #[allow(unused_variables)]
    let listen_addr = listener.local_addr().unwrap();

    loop {
        let (incoming, peer_addr) = tokio::select! {
            r = listener.accept() => {
                r?
            }
            _ = cancel_waiter.wait() => {
                debug!("listen canceled");
                return Ok(());
            }
        };

        let hash = config.hash();
        let cancel_waiter = cancel_waiter.clone();
        let server_policy = server_policy.clone();

        let str_addr = peer_addr.as_ref().map(|d| d.to_string());
        let span = info_span!(
            "trojan.client",
            peer.addr = str_addr.as_ref().map(|d| d.as_str()).unwrap_or("unknown")
        );
        tokio::task::spawn(
            process_incoming(
                cancel_waiter,
                incoming,
                peer_addr,
                hash,
                request_recv_timeout,
                idle_timeout,
                server_policy,
                #[cfg(feature = "statistics")]
                bu_context.clone(),
            )
            .instrument(span),
        );
    }
}

async fn process_incoming(
    cancel_waiter: CancelWaiter,
    mut incoming: impl StreamConnection + 'static,
    peer_addr: Option<SocketAddr>,
    cfg_hash: Arc<[u8]>,
    request_recv_timeout: Duration,
    idle_timeout: Duration,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
) -> CloseReason {
    let request = match read_request(&cancel_waiter, &mut incoming, cfg_hash.as_ref(), request_recv_timeout).await {
        Ok(request) => request,
        Err(close_reason) => return close_reason,
    };

    match request {
        RequestHeader::TcpConnect(_, addr) => {
            let addr = ServerAddr::from(addr);
            let span = info_span!("connection", target = addr.to_string());
            async move {
                tokio::select! {
                    r = stream::serve_tcp(incoming, peer_addr, addr, idle_timeout, server_policy, #[cfg(feature = "statistics")] bu_context) => { r }
                    _ = cancel_waiter.wait() => {
                        CloseReason::Canceled
                    }
                }
            }
            .instrument(span)
            .await
        }
        RequestHeader::UdpAssociate(_) => {
            udp::serve_udp(&cancel_waiter, incoming, peer_addr, idle_timeout, server_policy)
                .instrument(info_span!("udp-session"))
                .await
        }
    }
}

async fn read_request(
    cancel_waiter: &CancelWaiter,
    stream: &mut impl StreamConnection,
    cfg_hash: &[u8],
    request_recv_timeout: Duration,
) -> Result<RequestHeader, CloseReason> {
    let request_recv_timeout =
        request_recv_timeout + Duration::from_secs(rand::random::<u64>() % request_recv_timeout.as_secs());

    tokio::select! {
        r = time::timeout(request_recv_timeout, RequestHeader::read_from(stream, cfg_hash)) => {
            match r {
                Ok(Ok(r)) => Ok(r),
                Ok(Err(err)) => {
                    error!(error = ?err, "read request error");
                    Err(CloseReason::SockError)
                }
                Err(err) => {
                    error!(error = ?err, timeout = request_recv_timeout.as_secs(), "read request timeout");
                    Err(CloseReason::RequestTimeout)
                }
            }
        }
        _ = cancel_waiter.wait() => {
            error!("read request canceled");
            Err(CloseReason::Canceled)
        }
    }
}
