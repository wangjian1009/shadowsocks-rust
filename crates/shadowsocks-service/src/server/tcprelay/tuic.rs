use super::*;
use cfg_if::cfg_if;

use async_trait::async_trait;
use shadowsocks::{
    config::TuicConfig,
    lookup_then,
    net::{sys::create_inbound_udp_socket, FlowStat},
    tuic,
};

use super::super::udprelay::tuic::TuicUdpSocket;

pub struct TuicServerPolicy {
    context: Arc<ServiceContext>,
    max_udp_packet_size: usize,
}

#[async_trait]
impl tuic::server::ServerPolicy for TuicServerPolicy {
    async fn create_outbound_udp_socket(
        &self,
        assoc_id: u32,
        peer_addr: SocketAddr,
    ) -> io::Result<Box<dyn tuic::server::UdpSocket>> {
        let udp_socket = TuicUdpSocket::new(self.context.clone(), self.max_udp_packet_size, peer_addr, assoc_id);

        Ok(Box::new(udp_socket) as Box<dyn tuic::server::UdpSocket>)
    }

    fn create_connection_flow_state(&self) -> Option<Arc<FlowStat>> {
        Some(self.context.flow_stat())
    }

    fn connection_check_process_local(&self, target_addr: &tuic::server::Address) -> bool {
        cfg_if! {
            if #[cfg(feature = "server-mock")] {
                let target_addr = match target_addr.clone() {
                    tuic::server::Address::DomainAddress(h, p) => shadowsocks::relay::Address::DomainNameAddress(h, p),
                    tuic::server::Address::SocketAddress(a) => shadowsocks::relay::Address::SocketAddress(a),
                };

                match self.context.mock_server_protocol(&target_addr) {
                    Some(protocol) => match protocol {
                        ServerMockProtocol::DNS => return true
                    },
                    None => {}
                }
            }
        }

        false
    }

    async fn connection_process_local(
        &self,
        peer_addr: &SocketAddr,
        target_addr: tuic::server::Address,
        mut r: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        mut w: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    ) -> io::Result<()> {
        cfg_if! {
            if #[cfg(feature = "server-mock")] {
                let target_addr = match target_addr {
                    tuic::server::Address::DomainAddress(h, p) => shadowsocks::relay::Address::DomainNameAddress(h, p),
                    tuic::server::Address::SocketAddress(a) => shadowsocks::relay::Address::SocketAddress(a),
                };

                match self.context.mock_server_protocol(&target_addr) {
                    Some(protocol) => match protocol {
                        ServerMockProtocol::DNS => {
                            run_dns_tcp_stream(
                                self.context.dns_resolver(),
                                peer_addr,
                                &target_addr,
                                &mut r,
                                &mut w,
                            )
                                .await?;
                            return Ok(());
                        }
                    },
                    None => {}
                }
            }
        }

        unreachable!()
    }

    #[cfg(feature = "rate-limit")]
    fn create_connection_rate_limit(&self) -> std::io::Result<Option<shadowsocks::transport::RateLimiter>> {
        match self.context.connection_bound_width() {
            Some(bound_width) => Ok(Some(shadowsocks::transport::RateLimiter::new(Some(
                bound_width.clone(),
            ))?)),
            None => Ok(None),
        }
    }

    async fn check_outbound_blocked(&self, addr: &tuic::server::Address) -> bool {
        let addr = match addr.clone() {
            tuic::server::Address::DomainAddress(h, p) => shadowsocks::relay::Address::DomainNameAddress(h, p),
            tuic::server::Address::SocketAddress(a) => shadowsocks::relay::Address::SocketAddress(a),
        };
        self.context.check_outbound_blocked(&addr).await
    }

    fn check_client_blocked(&self, addr: &SocketAddr) -> bool {
        self.context.check_client_blocked(addr)
    }
}

impl TuicServerPolicy {
    pub fn new(context: Arc<ServiceContext>, max_udp_packet_size: usize) -> Self {
        Self {
            context,
            max_udp_packet_size,
        }
    }
}

impl TcpServer {
    pub async fn serve_tuic(self, svr_cfg: &ServerConfig, tuic_cfg: &TuicConfig) -> io::Result<()> {
        if svr_cfg.acceptor_transport().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "tuic protocol not support transport!",
            ));
        }

        let runtime_cfg = tuic::server::Config::new(match tuic_cfg {
            TuicConfig::Server((c, _)) => c,
            TuicConfig::Client(_c) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "tuic server can`t run with client config!",
                ))
            }
        })?;

        let socket = match svr_cfg.addr() {
            ServerAddr::SocketAddr(sa) => create_inbound_udp_socket(sa, self.accept_opts.ipv6_only).await?,
            ServerAddr::DomainName(domain, port) => {
                lookup_then!(&self.context.context(), domain, *port, |addr| {
                    create_inbound_udp_socket(&addr, self.accept_opts.ipv6_only).await
                })?
                .1
            }
        };

        let server = tuic::server::Server::init(
            runtime_cfg.server_config,
            socket.into_std()?,
            runtime_cfg.token,
            runtime_cfg.authentication_timeout,
            Box::new(TuicServerPolicy::new(
                self.context.clone(),
                runtime_cfg.max_udp_relay_packet_size,
            )),
        )?;

        info!("{} server listening on {}", svr_cfg.protocol().name(), svr_cfg.addr());
        server.run().await;
        Ok(())
    }
}
