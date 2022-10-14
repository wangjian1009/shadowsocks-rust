use super::*;

use async_trait::async_trait;
use shadowsocks::{config::TuicConfig, lookup_then, net::sys::create_inbound_udp_socket, tuic};
use tracing::{info, Instrument};

use super::super::udprelay::tuic::TuicUdpSocket;
use crate::server::policy::ServerPolicy;

pub struct TuicUdpCreator {
    context: Arc<ServiceContext>,
    max_udp_packet_size: usize,
}

#[async_trait]
impl tuic::server::UdpSocketCreator for TuicUdpCreator {
    async fn create_outbound_udp_socket(&self) -> io::Result<Box<dyn tuic::server::UdpSocket>> {
        let udp_socket = TuicUdpSocket::new(self.context.clone(), self.max_udp_packet_size);
        Ok(Box::new(udp_socket) as Box<dyn tuic::server::UdpSocket>)
    }
}

impl TuicUdpCreator {
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

        let tuic_cfg = match tuic_cfg {
            TuicConfig::Server((c, _)) => c,
            TuicConfig::Client(_c) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "tuic server can`t run with client config!",
                ))
            }
        };

        let authentication_timeout = svr_cfg.timeout().clone().unwrap_or_else(|| Duration::from_secs(1000));
        let idle_timeout = svr_cfg
            .idle_timeout()
            .clone()
            .unwrap_or_else(|| Duration::from_secs(15000));

        info!(
            net = "udp",
            proto = svr_cfg.protocol().name(),
            tuic.cc = tuic_cfg.congestion_controller.to_string(),
            tuic.mtu = tuic_cfg.max_udp_relay_packet_size,
            timeout.idle = idle_timeout.as_millis(),
            timeout.authentication = authentication_timeout.as_millis(),
            message = "protocol detail",
        );

        let socket = match svr_cfg.addr() {
            ServerAddr::SocketAddr(sa) => create_inbound_udp_socket(sa, self.accept_opts.ipv6_only).await?,
            ServerAddr::DomainName(domain, port) => {
                lookup_then!(&self.context.context(), domain, *port, |addr| {
                    create_inbound_udp_socket(&addr, self.accept_opts.ipv6_only).await
                })?
                .1
            }
        };

        let tokens = tuic_cfg.build_tokens();
        let server_cfg = tuic_cfg.build_server_config(idle_timeout.clone())?;

        let server = tuic::server::Server::init(
            server_cfg,
            socket.into_std()?,
            tokens,
            authentication_timeout,
            idle_timeout,
            Arc::new(Box::new(TuicUdpCreator::new(
                self.context.clone(),
                tuic_cfg.max_udp_relay_packet_size,
            ))),
            Arc::new(Box::new(ServerPolicy::new(self.context.clone(), svr_cfg.timeout()))),
        )?;

        info!("tuic listening on {}", svr_cfg.addr());
        server.run(self.context.cancel_waiter()).in_current_span().await;
        Ok(())
    }
}
