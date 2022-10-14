use self::{
    authenticate::IsAuthenticated,
    dispatch::DispatchError,
    udp::{UdpSessionCloseReason, UdpSessionMap, UdpSessionSource},
};
use parking_lot::Mutex;
use quinn::{Connecting, Connection as QuinnConnection, ConnectionError, NewConnection, SendStream};
use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tracing::{debug, error, info, trace, Instrument};

use super::super::protocol::Command;
use super::UdpSocketCreator;

use crate::{
    canceler::{CancelWaiter, Canceler},
    net::FlowStat,
    policy::ServerPolicy,
    timeout::TimeoutWaiter,
};

mod authenticate;
mod dispatch;
mod stream;
mod udp;

#[derive(Clone)]
pub struct Connection {
    controller: QuinnConnection,
    udp_sessions: Arc<UdpSessionMap>,
    token: Arc<HashSet<[u8; 32]>>,
    is_authenticated: IsAuthenticated,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    flow_state: Option<Arc<FlowStat>>,
    idle_timeout: Duration,
}

impl Connection {
    pub async fn handle(
        conn: Connecting,
        token: Arc<HashSet<[u8; 32]>>,
        auth_timeout: Duration,
        idle_timeout: Duration,
        udp_socket_creator: Arc<Box<dyn UdpSocketCreator>>,
        server_policy: Arc<Box<dyn ServerPolicy>>,
        cancel_waiter: CancelWaiter,
    ) {
        let (connection, mut uni_streams, mut bi_streams, mut datagrams) = match conn.await {
            Ok(NewConnection {
                connection,
                uni_streams,
                bi_streams,
                datagrams,
                ..
            }) => (connection, uni_streams, bi_streams, datagrams),
            Err(err) => {
                error!(error = ?err, "connecting error");
                return;
            }
        };

        let canceler = Canceler::new();
        let auth_timeout_waiter = TimeoutWaiter::new(auth_timeout);
        tokio::pin!(auth_timeout_waiter);
        let idle_timeout_waiter = TimeoutWaiter::new(idle_timeout.clone());
        tokio::pin!(idle_timeout_waiter);

        info!("establish");

        let (udp_sessions, mut recv_pkt_rx, mut session_close_rx) =
            UdpSessionMap::new(idle_timeout.clone(), udp_socket_creator.clone());
        let is_closed = IsClosed::new();
        let is_authed = IsAuthenticated::new(is_closed.clone());

        let flow_state = server_policy.create_connection_flow_state();
        let conn = Self {
            controller: connection,
            udp_sessions: Arc::new(udp_sessions),
            token,
            is_authenticated: is_authed,
            server_policy,
            flow_state,
            idle_timeout: idle_timeout.clone(),
        };

        let mut is_authed = false;
        let err = loop {
            tokio::select! {
                // listen_uni_streams
                r = uni_streams.next() => {
                    idle_timeout_waiter.tick();

                    let stream = match r {
                        Some(Ok(s)) => s,
                        Some(Err(err)) => break err,
                        None => break ConnectionError::LocallyClosed,
                    };

                    let conn = conn.clone();
                    let conn_waiter = canceler.waiter();
                    tokio::spawn(async move {
                        tokio::select! {
                            r = conn.process_uni_stream(stream) => {
                                if let Err(err) = r {
                                    conn.close(err);
                                    if !is_authed {
                                        conn.is_authenticated.wake();
                                    }
                                }
                            }
                            _ = conn_waiter.wait() => {}
                        }
                    }.in_current_span());
                },
                // listen_bi_streams
                r = bi_streams.next() => {
                    idle_timeout_waiter.tick();

                    let (send, recv) = match r {
                        Some(r) => match r {
                            Ok(s) => s,
                            Err(err) => break err,
                        },
                        None => break ConnectionError::LocallyClosed,
                    };

                    let conn = conn.clone();
                    let conn_waiter = canceler.waiter();
                    tokio::spawn(async move {
                        tokio::select! {
                            r = conn.process_bi_stream(send, recv, conn_waiter.clone()) => {
                                if let Err(err) = r {
                                    conn.close(err);
                                }
                            }
                            _ = conn_waiter.wait() => {}
                        }
                    }.in_current_span());
                },
                // listen_datagrams
                r = datagrams.next() => {
                    idle_timeout_waiter.tick();

                    let datagram = match r {
                        Some(r) => match r {
                            Ok(s) => s,
                            Err(err) => break err,
                        },
                        None => break ConnectionError::LocallyClosed,
                    };

                    let conn = conn.clone();
                    let conn_waiter = canceler.waiter();
                    tokio::spawn(async move {
                        tokio::select! {
                            r = conn.process_datagram(datagram) => {
                                if let Err(err) = r {
                                    conn.close(err);
                                }
                            }
                            _ = conn_waiter.wait() => {}
                        }
                    }.in_current_span());
                },
                // listen_received_udp_packet
                r = recv_pkt_rx.recv() => {
                    idle_timeout_waiter.tick();

                    let (assoc_id, pkt, addr) = match r {
                        Some((assoc_id, pkt, addr)) => (assoc_id, pkt, addr),
                        None => break ConnectionError::LocallyClosed,
                    };

                    let conn = conn.clone();
                    let conn_waiter = canceler.waiter();
                    tokio::spawn(async move {
                        tokio::select! {
                            r = conn.process_received_udp_packet(assoc_id, pkt, addr) => {
                                if let Err(err) = r {
                                    conn.close(err);
                                }
                            }
                            _ = conn_waiter.wait() => {}
                        }
                    }.in_current_span());
                }
                // auth
                _r = conn.is_authenticated.clone(), if !is_authed => {
                    is_authed = true;
                    idle_timeout_waiter.tick();
                },
                // auth timeout
                _r = &mut auth_timeout_waiter, if !is_authed => {
                    debug!("auth timeout");
                    conn.close(DispatchError::AuthenticationTimeout);
                    conn.is_authenticated.wake();
                    is_authed = true;
                },
                // idle timeout
                _r = &mut idle_timeout_waiter, if is_authed => {
                    debug!("idle timeout");
                    conn.close(DispatchError::IdleTimeout);
                },
                r = session_close_rx.recv() => {
                    if let Some((assoc_id, close_reason)) = r {
                        let udp_sessions = conn.udp_sessions.clone();

                        tokio::spawn(async move {
                            let _ = udp_sessions.dissociate(assoc_id, close_reason).await;
                        }.in_current_span());
                    }
                    else {
                        panic!("session close channel closed");
                    }
                }
                // cancel
                _r = cancel_waiter.wait() => {
                    debug!("canceled");
                    conn.close(DispatchError::Shutdown);
                    if !is_authed {
                        conn.is_authenticated.wake();
                        is_authed = true;
                    }
                }
            }
        };

        canceler.cancel();
        is_closed.set_closed();

        match err {
            ConnectionError::TimedOut => {
                debug!(reason = "connection timeout", "disconnect")
            }
            ConnectionError::LocallyClosed => {
                debug!(reason = "locally closed", "disconnect")
            }
            err => error!(reason = "error", error = ?err, "disconnect"),
        }

        // 清理所有udp会话
        for session_id in conn.udp_sessions.session_ids().into_iter() {
            let udp_sessions = conn.udp_sessions.clone();
            tokio::spawn(
                async move {
                    let _ = udp_sessions
                        .dissociate(session_id, UdpSessionCloseReason::Shutdown)
                        .await;
                }
                .in_current_span(),
            );
        }
    }

    fn close(&self, err: DispatchError) {
        trace!(reason = ?err, "call close");
        self.controller.close(err.as_error_code(), err.to_string().as_bytes());
    }
}

#[derive(Clone)]
pub struct IsClosed(Arc<IsClosedInner>);

struct IsClosedInner {
    is_closed: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl IsClosed {
    fn new() -> Self {
        Self(Arc::new(IsClosedInner {
            is_closed: AtomicBool::new(false),
            waker: Mutex::new(None),
        }))
    }

    fn set_closed(&self) {
        self.0.is_closed.store(true, Ordering::Release);

        if let Some(waker) = self.0.waker.lock().take() {
            waker.wake();
        }
    }

    fn check(&self) -> bool {
        self.0.is_closed.load(Ordering::Acquire)
    }
}

impl Future for IsClosed {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.0.is_closed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            *self.0.waker.lock() = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[inline]
async fn write_response(mut send: SendStream, is_success: bool) -> Option<SendStream> {
    let resp = Command::new_response(is_success);
    if let Err(err) = resp.write_to(&mut send).await {
        error!(error = ?err, "write response failed");
        return None;
    }

    if is_success {
        Some(send)
    } else {
        None
    }
}
