use self::{
    authenticate::IsAuthenticated,
    dispatch::DispatchError,
    udp::{UdpPacketFrom, UdpPacketSource, UdpSessionMap},
};
use parking_lot::Mutex;
use quinn::{Connecting, Connection as QuinnConnection, ConnectionError, NewConnection};
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

use super::UdpSocketCreator;
use crate::{net::FlowStat, policy::ServerPolicy};

mod authenticate;
mod dispatch;
mod task;
mod udp;

#[derive(Clone)]
pub struct Connection {
    controller: QuinnConnection,
    udp_packet_from: UdpPacketFrom,
    udp_sessions: Arc<UdpSessionMap>,
    token: Arc<HashSet<[u8; 32]>>,
    is_authenticated: IsAuthenticated,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    flow_state: Option<Arc<FlowStat>>,
}

impl Connection {
    pub async fn handle(
        conn: Connecting,
        token: Arc<HashSet<[u8; 32]>>,
        auth_timeout: Duration,
        udp_socket_creator: Arc<Box<dyn UdpSocketCreator>>,
        server_policy: Arc<Box<dyn ServerPolicy>>,
    ) {
        let rmt_addr = conn.remote_address();
        let (connection, mut uni_streams, mut bi_streams, mut datagrams) = match conn.await {
            Ok(NewConnection {
                connection,
                uni_streams,
                bi_streams,
                datagrams,
                ..
            }) => (connection, uni_streams, bi_streams, datagrams),
            Err(err) => {
                tracing::error!("[{rmt_addr}] [connecting] {err}");
                return;
            }
        };

        let auth_deadline = tokio::time::Instant::now() + auth_timeout;

        tracing::info!("[{rmt_addr}] [establish]");

        let (udp_sessions, mut recv_pkt_rx) = UdpSessionMap::new(udp_socket_creator.clone());
        let is_closed = IsClosed::new();
        let is_authed = IsAuthenticated::new(is_closed.clone());

        let flow_state = server_policy.create_connection_flow_state();
        let conn = Self {
            controller: connection,
            udp_packet_from: UdpPacketFrom::new(),
            udp_sessions: Arc::new(udp_sessions),
            token,
            is_authenticated: is_authed,
            server_policy,
            flow_state,
        };

        let mut is_authed = false;
        let err = loop {
            tokio::select! {
                // listen_uni_streams
                r = uni_streams.next() => {
                    let stream = match r {
                        Some(r) => match r {
                            Ok(s) => s,
                            Err(err) => break err,
                        },
                        None => break ConnectionError::LocallyClosed,
                    };

                    let conn = conn.clone();
                    tokio::spawn(async move {
                        match conn.process_uni_stream(stream).await {
                            Ok(()) => {}
                            Err(err) => {
                                conn.controller.close(err.as_error_code(), err.to_string().as_bytes());

                                let rmt_addr = conn.controller.remote_address();
                                tracing::error!("[{rmt_addr}] {err}");
                            }
                        }
                    });
                },
                // listen_bi_streams
                r = bi_streams.next() => {
                    let (send, recv) = match r {
                        Some(r) => match r {
                            Ok(s) => s,
                            Err(err) => break err,
                        },
                        None => break ConnectionError::LocallyClosed,
                    };

                    let conn = conn.clone();
                    tokio::spawn(async move {
                        match conn.process_bi_stream(send, recv).await {
                            Ok(()) => {}
                            Err(err) => {
                                conn.controller.close(err.as_error_code(), err.to_string().as_bytes());

                                let rmt_addr = conn.controller.remote_address();
                                tracing::error!("[{rmt_addr}] {err}");
                            }
                        }
                    });
                },
                // listen_datagrams
                r = datagrams.next() => {
                    let datagram = match r {
                        Some(r) => match r {
                            Ok(s) => s,
                            Err(err) => break err,
                        },
                        None => break ConnectionError::LocallyClosed,
                    };

                    let conn = conn.clone();
                    tokio::spawn(async move {
                        match conn.process_datagram(datagram).await {
                            Ok(()) => {}
                            Err(err) => {
                                conn.controller.close(err.as_error_code(), err.to_string().as_bytes());

                                let rmt_addr = conn.controller.remote_address();
                                tracing::error!("[{rmt_addr}] {err}");
                            }
                        }
                    });
                },
                // listen_received_udp_packet
                r = recv_pkt_rx.recv() => {
                    let (assoc_id, pkt, addr) = match r {
                        Some((assoc_id, pkt, addr)) => (assoc_id, pkt, addr),
                        None => break ConnectionError::LocallyClosed,
                    };

                    let conn = conn.clone();
                    tokio::spawn(async move {
                        match conn.process_received_udp_packet(assoc_id, pkt, addr).await {
                            Ok(()) => {}
                            Err(err) => {
                                conn.controller.close(err.as_error_code(), err.to_string().as_bytes());

                                let rmt_addr = conn.controller.remote_address();
                                tracing::error!("[{rmt_addr}] {err}");
                            }
                        }
                    });
                }
                // auth
                _r = conn.is_authenticated.clone(), if !is_authed => {
                    is_authed = true;
                },
                // auth timeout
                _r = tokio::time::sleep_until(auth_deadline), if !is_authed => {
                    let err = DispatchError::AuthenticationTimeout;

                    conn.controller.close(err.as_error_code(), err.to_string().as_bytes());
                    conn.is_authenticated.wake();

                    let rmt_addr = conn.controller.remote_address();
                    tracing::error!("[{rmt_addr}] {err}");

                    is_authed = true;
                    // break ConnectionError::LocallyClosed;
                },
            }
        };

        is_closed.set_closed();

        match err {
            ConnectionError::TimedOut => {
                tracing::debug!("[{rmt_addr}] [disconnect] [connection timeout]")
            }
            ConnectionError::LocallyClosed => {
                tracing::debug!("[{rmt_addr}] [disconnect] [locally closed]")
            }
            err => tracing::error!("[{rmt_addr}] [disconnect] {err}"),
        }
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
