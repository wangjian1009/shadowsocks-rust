use async_trait::async_trait;
use cfg_if::cfg_if;
use shadowsocks::policy::StreamAction;
use std::{future::Future, io, net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::Duration,
};

use shadowsocks::net::{FlowStat, TcpStream};
use shadowsocks::{policy, relay::Address};

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
        tokio::spawn(async move {
            context
                .connection_stat_ref()
                .remove_in_connection(&connection_ctx.0, connection_ctx.1)
                .await;
        });
    }
}

/// OutConnectionGuard
pub struct OutConnectionGuard {
    _guard: super::connection::OutConnectionGuard,
}

impl policy::ConnectionGuard for OutConnectionGuard {}

cfg_if! {
    if #[cfg(feature = "server-mock")] {
        use super::context::ServerMockProtocol;

        /// LocalProcessor
        pub struct LocalProcessor {
            context: Arc<ServiceContext>,
            peer_addr: SocketAddr,
            target_addr: Address,
            protocol: ServerMockProtocol,
            _remote_guard: InConnectionGuard,
        }

        #[async_trait]
        impl policy::LocalProcessor for LocalProcessor {
            async fn process(
                &self,
                mut r: Box<dyn AsyncRead + Send + Unpin>,
                mut w: Box<dyn AsyncWrite + Send + Unpin>,
            ) -> io::Result<()>
            {
                match self.protocol {
                    ServerMockProtocol::DNS => {
                        run_dns_tcp_stream(
                            self.context.dns_resolver(),
                            &self.peer_addr,
                            &self.target_addr,
                            &mut r,
                            &mut w,
                        )
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
    connect_timeout: Option<Duration>,
}

impl ServerPolicy {
    pub fn new(context: Arc<ServiceContext>, connect_timeout: Option<Duration>) -> Self {
        Self {
            context,
            connect_timeout,
        }
    }
}

#[async_trait]
impl policy::ServerPolicy for ServerPolicy {
    fn create_connection_flow_state(&self) -> Option<Arc<FlowStat>> {
        Some(self.context.flow_stat())
    }

    async fn create_out_connection(
        &self,
        target_addr: &Address,
    ) -> io::Result<(TcpStream, Box<dyn policy::ConnectionGuard>)> {
        let stream = timeout_fut(
            self.connect_timeout.clone(),
            shadowsocks::net::TcpStream::connect_remote_with_opts(
                self.context.context_ref(),
                target_addr,
                self.context.connect_opts_ref(),
            ),
        )
        .await?;

        Ok((
            stream,
            Box::new(OutConnectionGuard {
                _guard: self.context.connection_stat().add_out_connection(),
            }) as Box<dyn policy::ConnectionGuard>,
        ))
    }

    async fn stream_check(&self, src_addr: &SocketAddr, target_addr: &Address) -> io::Result<policy::StreamAction> {
        let connection_stat = self.context.connection_stat();

        let connection_ctx = match connection_stat
            .check_add_in_connection(src_addr.clone(), self.context.limit_connection_per_ip())
            .await
        {
            Ok((c, b)) => (c.id, b),
            Err(_err) => {
                match self.context.limit_connection_close_delay() {
                    None => log::error!(
                        "tcp server: from {} limit {} reached, close immediately",
                        src_addr,
                        self.context.limit_connection_per_ip().unwrap(),
                    ),
                    Some(delay) => {
                        log::error!(
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
                if let Some(protocol) = self.context.mock_server_protocol(&target_addr) {
                    return Ok(policy::StreamAction::Local {
                        processor: Box::new(LocalProcessor {
                            context: self.context.clone(),
                            peer_addr: src_addr.clone(),
                            target_addr: target_addr.clone(),
                            protocol: protocol.clone(),
                            _remote_guard: remote_guard,
                        })
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

    async fn packet_check(&self, src_addr: &SocketAddr, target_addr: &Address) -> io::Result<policy::PacketAction> {
        if self.context.check_client_blocked(src_addr) {
            return Ok(policy::PacketAction::ClientBlocked);
        }

        if self.context.check_outbound_blocked(target_addr).await {
            return Ok(policy::PacketAction::OutboundBlocked);
        }

        Ok(policy::PacketAction::Remote)
    }
}

async fn timeout_fut<F, R>(duration: Option<Duration>, f: F) -> io::Result<R>
where
    F: Future<Output = io::Result<R>> + Send,
{
    match duration {
        None => f.await,
        Some(d) => match tokio::time::timeout(d, f).await {
            Ok(o) => o,
            Err(..) => Err(io::ErrorKind::TimedOut.into()),
        },
    }
}
