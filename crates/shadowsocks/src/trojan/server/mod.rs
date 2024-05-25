use std::fmt;
use std::net::SocketAddr;
use std::{io, sync::Arc};
use tokio::time::{self, Duration};
use tracing::{debug, error, info_span, Instrument};

use crate::{
    canceler::Canceler,
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
            Self::IdleTimeout => write!(f, "idle-timeout"),
            Self::RequestTimeout => write!(f, "request-timeout"),
            Self::InternalError => write!(f, "internal"),
        }
    }
}

pub async fn serve(
    mut listener: impl Acceptor + 'static,
    canceler: Arc<Canceler>,
    config: &Config,
    request_recv_timeout: Duration,
    idle_timeout: Duration,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
) -> io::Result<()> {
    #[allow(unused_variables)]
    let listen_addr = listener.local_addr().unwrap();
    let mut cancel_waiter = canceler.waiter();

    loop {
        tokio::select! {
            r = listener.accept() => {
                let (incoming, peer_addr) = r?;

                let hash = config.hash();
                let server_policy = server_policy.clone();

                let str_addr = peer_addr.as_ref().map(|d| d.to_string());
                let span = info_span!("trojan.client", peer.addr = str_addr.as_deref().unwrap_or("unknown"));

                let mut cancel_waiter = canceler.waiter();

                #[cfg(feature = "statistics")]
                let bu_context = bu_context.clone();

                tokio::task::spawn(
                    async move {
                        tokio::select! {
                            _ = process_incoming(
                                incoming,
                                peer_addr,
                                hash,
                                request_recv_timeout,
                                idle_timeout,
                                server_policy,
                                #[cfg(feature = "statistics")]
                                bu_context,
                            ) => {
                            }
                            _ =  cancel_waiter.wait() => {
                                debug!("listen canceled");
                            }
                        }

                    }.instrument(span),
                );
            }
            _ =  cancel_waiter.wait() => {
                debug!("listen canceled");
                return Ok(());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_incoming(
    mut incoming: impl StreamConnection + 'static,
    peer_addr: Option<SocketAddr>,
    cfg_hash: Arc<[u8]>,
    request_recv_timeout: Duration,
    idle_timeout: Duration,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
) -> CloseReason {
    let request = match read_request(&mut incoming, cfg_hash.as_ref(), request_recv_timeout).await {
        Ok(request) => request,
        Err(close_reason) => return close_reason,
    };

    match request {
        RequestHeader::TcpConnect(_, addr) => {
            let addr = ServerAddr::from(addr);
            let span = info_span!("tcp", local=?peer_addr);
            stream::serve_tcp(
                incoming,
                peer_addr,
                addr,
                idle_timeout,
                server_policy,
                #[cfg(feature = "statistics")]
                bu_context,
            )
            .instrument(span)
            .await
        }
        RequestHeader::UdpAssociate(_) => {
            udp::serve_udp(
                incoming,
                peer_addr,
                idle_timeout,
                server_policy,
                #[cfg(feature = "statistics")]
                bu_context,
            )
            .instrument(info_span!("udp", local=?peer_addr))
            .await
        }
    }
}

async fn read_request(
    stream: &mut impl StreamConnection,
    cfg_hash: &[u8],
    request_recv_timeout: Duration,
) -> Result<RequestHeader, CloseReason> {
    let request_recv_timeout =
        request_recv_timeout + Duration::from_secs(rand::random::<u64>() % request_recv_timeout.as_secs());

    match time::timeout(request_recv_timeout, RequestHeader::read_from(stream, cfg_hash)).await {
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
