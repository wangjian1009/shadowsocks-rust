use std::{io, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::Duration,
};
use tracing::{debug, error, warn};

use crate::{
    policy::{ServerPolicy, StreamAction},
    relay::tcprelay::utils_copy::copy_bidirectional,
    timeout::TimeoutWaiter,
    transport::{MonTraffic, RateLimitedStream, StreamConnection},
    ServerAddr,
};

use super::*;

pub(super) async fn serve_tcp(
    incoming: impl StreamConnection + 'static,
    peer_addr: Option<SocketAddr>,
    target_addr: ServerAddr,
    idle_timeout: Duration,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
) -> CloseReason {
    match server_policy
        .stream_check(
            peer_addr.as_ref(),
            &target_addr,
            #[cfg(feature = "statistics")]
            bu_context.clone(),
        )
        .await
    {
        Err(err) => {
            warn!(error = ?err, "policy check error");
            CloseReason::InternalError
        }
        Ok(StreamAction::ClientBlocked) => {
            warn!("client blocked by ACL rules");
            CloseReason::ClientBlocked
        }
        Ok(StreamAction::OutboundBlocked) => {
            warn!("outbound blocked by ACL rules");
            CloseReason::OutboundBlocked
        }
        Ok(StreamAction::ConnectionLimited) => {
            warn!("connection limited");
            CloseReason::ClientBlocked
        }
        Ok(StreamAction::Remote {
            connection_guard: _,
            #[cfg(feature = "rate-limit")]
            rate_limit,
        }) => {
            #[allow(unused_mut)]
            let (mut target, _guard) = match server_policy
                .create_out_connection(
                    peer_addr.as_ref(),
                    target_addr,
                    #[cfg(feature = "statistics")]
                    bu_context,
                )
                .await
            {
                Ok(s) => s,
                Err(err) => {
                    error!(error = ?err, "create out connection fail");
                    return CloseReason::InternalError;
                }
            };

            #[cfg(feature = "rate-limit")]
            let mut target = RateLimitedStream::from_stream(target, rate_limit);

            let mut incoming = MonTraffic::new(incoming, server_policy.create_connection_flow_state_tcp());

            let (down, up, r) = copy_bidirectional(&mut target, &mut incoming, Some(idle_timeout)).await;
            match r {
                Ok(()) => {
                    debug!(up, down, "transfer finished");
                    CloseReason::SockClosed
                }
                Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {
                    debug!(up, down, error = ?err, "transfer reset");
                    CloseReason::SockClosed
                }
                Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                    debug!(up, down, "transfer timeout");
                    CloseReason::IdleTimeout
                }
                Err(err) => {
                    error!(up, down, error = ?err, "transfer error");
                    CloseReason::SockError
                }
            }
        }
        Ok(StreamAction::Local { processor }) => {
            let (recv, send) = tokio::io::split(MonTraffic::new(
                incoming,
                server_policy.create_connection_flow_state_tcp(),
            ));
            let recv = Box::new(recv) as Box<dyn AsyncRead + Send + Unpin>;
            let send = Box::new(send) as Box<dyn AsyncWrite + Send + Unpin>;

            let timeout_waiter = TimeoutWaiter::new(idle_timeout);
            let timeout_ticker = timeout_waiter.ticker();

            tokio::pin!(timeout_waiter);

            let r = tokio::select! {
                r = processor.process(recv, send, Some(timeout_ticker)) => r,
                _ = &mut timeout_waiter => {
                    debug!("process timeout");
                    return CloseReason::IdleTimeout;
                }
            };

            match r {
                Ok(()) => {
                    debug!("process finished for closed");
                    CloseReason::SockClosed
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    debug!("process finished for closed");
                    CloseReason::SockClosed
                }
                Err(err) => {
                    error!(error = ?err, "process finished with error");
                    CloseReason::InternalError
                }
            }
        }
    }
}
