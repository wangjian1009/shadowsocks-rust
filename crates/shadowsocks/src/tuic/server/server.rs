use quinn::{Endpoint, Incoming, ServerConfig};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{collections::HashSet, io::Result, sync::Arc, time::Duration};
use tracing::{info, info_span, trace, Instrument};

use crate::{canceler::CancelWaiter, policy::ServerPolicy};

use super::connection::Connection;

pub struct Server {
    endpoint: Endpoint,
    incoming: Incoming,
    token: Arc<HashSet<[u8; 32]>>,
    authentication_timeout: Duration,
    idle_timeout: Duration,
    policy: Arc<Box<dyn ServerPolicy>>,
    #[cfg(feature = "statistics")]
    bu_context: crate::statistics::BuContext,
}

impl Server {
    pub fn init(
        config: ServerConfig,
        socket: std::net::UdpSocket,
        token: HashSet<[u8; 32]>,
        auth_timeout: Duration,
        idle_timeout: Duration,
        policy: Arc<Box<dyn ServerPolicy>>,
        #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
    ) -> Result<Self> {
        let (endpoint, incoming) = Endpoint::server(
            config,
            match socket.local_addr()? {
                SocketAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                SocketAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            },
        )?;
        endpoint.rebind(socket)?;

        Ok(Self {
            endpoint,
            incoming,
            token: Arc::new(token),
            authentication_timeout: auth_timeout,
            idle_timeout,
            policy,
            #[cfg(feature = "statistics")]
            bu_context,
        })
    }

    pub async fn run(mut self, cancel_waiter: CancelWaiter) {
        loop {
            tokio::select! {
                r = self.incoming.next().in_current_span() => {
                    if let Some(conn) = r {
                        let token = self.token.clone();

                        let span = info_span!("tuic.client", peer.addr = conn.remote_address().to_string());
                        tokio::spawn(
                            Connection::handle(
                                conn,
                                token,
                                self.authentication_timeout,
                                self.idle_timeout,
                                self.policy.clone(),
                                cancel_waiter.clone(),
                                #[cfg(feature = "statistics")]
                                self.bu_context.clone(),
                            )
                            .instrument(span),
                        );
                    }
                    else {
                        info!("tuic stoped");
                        return;
                    }
                }
                _ = cancel_waiter.wait(), if !cancel_waiter.is_canceled() => {
                    trace!("tuic cancel received");
                    self.endpoint.close(quinn::VarInt::from_u32(1), "shutdown".as_bytes());
                }
            }
        }
    }
}
