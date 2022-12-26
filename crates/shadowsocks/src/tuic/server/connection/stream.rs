use cfg_if::cfg_if;
use quinn::{ConnectionError, ReadExactError, RecvStream, SendDatagramError, SendStream, WriteError};
use tracing::{debug, error, warn};

use std::time::Duration;
use std::{
    io::{Error as IoError, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    net::FlowStat,
    policy::{ServerPolicy, StreamAction},
    relay::tcprelay::utils_copy::copy_bidirectional,
    timeout::TimeoutWaiter,
    transport::{MonTraffic, MonTrafficRead, MonTrafficWrite},
    ServerAddr,
};

use super::write_response;

#[cfg(feature = "rate-limit")]
use crate::transport::RateLimitedStream;

pub async fn connect(
    server_policy: Arc<Box<dyn ServerPolicy>>,
    peer_addr: &SocketAddr,
    mut send: SendStream,
    recv: RecvStream,
    addr: ServerAddr,
    flow_state: Option<Arc<FlowStat>>,
    idle_timeout: Duration,
    #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
) {
    match server_policy
        .stream_check(Some(&ServerAddr::SocketAddr(peer_addr.clone())), &addr)
        .await
    {
        Err(err) => {
            warn!(error = ?err, "ack check error");
            let _ = write_response(send, false).await;
            return;
        }
        Ok(StreamAction::ClientBlocked) => {
            warn!("client blocked by ACL rules");
            let _ = write_response(send, false).await;
            return;
        }
        Ok(StreamAction::OutboundBlocked) => {
            warn!("outbound blocked by ACL rules");
            let _ = write_response(send, false).await;
            return;
        }
        Ok(StreamAction::ConnectionLimited) => {
            warn!("connection limited");
            let _ = write_response(send, false).await;
            return;
        }
        Ok(StreamAction::Remote {
            connection_guard: _,
            #[cfg(feature = "rate-limit")]
            rate_limit,
        }) => {
            #[allow(unused_mut)]
            let (mut target, _guard) = match server_policy.create_out_connection(addr).await {
                Ok(s) => {
                    send = match write_response(send, true).await {
                        Some(send) => send,
                        None => return,
                    };
                    s
                }
                Err(err) => {
                    error!(error = ?err, "create out connection fail");
                    let _ = write_response(send, false).await;
                    return;
                }
            };

            let flow_state_tx = flow_state.clone();

            #[allow(unused_mut)]
            let mut tunnel = MonTraffic::new_with_tx_rx(BiStream(send, recv), flow_state_tx, flow_state.clone());

            #[cfg(feature = "statistics")]
            #[allow(unused_mut)]
            let mut tunnel = crate::statistics::MonTraffic::new(
                tunnel,
                bu_context.clone(),
                Some("total_traffic_bu_tx"),
                Some("total_traffic_bu_rx"),
            );

            cfg_if! {
                if #[cfg(feature = "rate-limit")] {
                    let mut tunnel =
                        RateLimitedStream::from_stream(tunnel, rate_limit.clone());

                    let mut target =
                        RateLimitedStream::from_stream(target, rate_limit);
                }
            }

            let (down, up, r) = copy_bidirectional(&mut target, &mut tunnel, Some(idle_timeout)).await;
            match r {
                Ok(()) => debug!(up, down, "transfer finished"),
                Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {
                    debug!(up, down, error = ?err, "transfer reset")
                }
                Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                    debug!(up, down, "transfer timeout")
                }
                Err(err) => error!(up, down, error = ?err, "transfer error"),
            }
        }
        Ok(StreamAction::Local { processor }) => {
            send = match write_response(send, true).await {
                Some(send) => send,
                None => return,
            };

            let send = MonTrafficWrite::new(send, flow_state.clone());
            let recv = MonTrafficRead::new(recv, flow_state);

            #[cfg(feature = "statistics")]
            let send = crate::statistics::MonTrafficWrite::new(send, bu_context.clone(), "total_traffic_bu_tx");
            #[cfg(feature = "statistics")]
            let recv = crate::statistics::MonTrafficRead::new(recv, bu_context.clone(), "total_traffic_bu_rx");

            let timeout_waiter = TimeoutWaiter::new(idle_timeout);
            let timeout_ticker = timeout_waiter.ticker();
            tokio::pin!(timeout_waiter);

            tokio::select! {
                r = processor.process(
                    Box::new(recv) as Box<dyn AsyncRead + Send + Unpin>,
                    Box::new(send) as Box<dyn AsyncWrite + Send + Unpin>,
                    Some(timeout_ticker),
                ) => {
                    match r {
                        Ok(()) => debug!("process finished"),
                        Err(err) => error!(error = ?err, "connection process fail"),
                    }
                }
                _ = &mut timeout_waiter => {
                    error!("process timeout");
                }
            }
        }
    }
}

struct BiStream(SendStream, RecvStream);

impl AsyncRead for BiStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.1).poll_read(cx, buf)
    }
}

impl AsyncWrite for BiStream {
    #[inline]
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[derive(Error, Debug)]
pub enum TaskError {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    ReadStream(#[from] ReadExactError),
    #[error(transparent)]
    WriteStream(#[from] WriteError),
    #[error(transparent)]
    SendDatagram(#[from] SendDatagramError),
}
