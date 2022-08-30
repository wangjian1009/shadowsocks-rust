use super::*;

use shadowsocks::{config::TuicConfig, lookup_then, net::sys::create_inbound_udp_socket, tuic};

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
            Box::new(super::super::udprelay::tuic::TuicUdpSocketCreator::new(
                self.context.clone(),
                runtime_cfg.max_udp_relay_packet_size,
            )),
        )?;

        info!("{} server listening on {}", svr_cfg.protocol().name(), svr_cfg.addr());
        server.run().await;
        Ok(())
    }
}
