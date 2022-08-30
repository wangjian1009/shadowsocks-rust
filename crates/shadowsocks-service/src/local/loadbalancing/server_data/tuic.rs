use shadowsocks::{
    config::TuicConfig,
    context::SharedContext,
    net::ConnectOpts,
    tuic::client::{relay_init, Config, Request, ServerAddr},
};
use std::{future::Future, io};

use tokio::sync::mpsc::Sender;

use super::*;

#[derive(Debug)]
pub struct TuicServerContext {
    req_tx: Sender<Request>,
}

impl ServerIdent {
    pub async fn tuic_run(
        &self,
        context: SharedContext,
        connect_opts: ConnectOpts,
        tuic_config: &TuicConfig,
    ) -> io::Result<impl Future<Output = std::io::Result<()>>> {
        let tuic_config = match tuic_config {
            TuicConfig::Client(c) => c,
            TuicConfig::Server(..) => unreachable!(),
        };

        let server_addr = match self.server_config().addr() {
            shadowsocks::ServerAddr::DomainName(domain, port) => ServerAddr::DomainAddr {
                domain: domain.clone(),
                port: port.clone(),
            },
            shadowsocks::ServerAddr::SocketAddr(addr) => {
                let sni = match tuic_config.sni.as_ref() {
                    Some(sni) => sni,
                    None => return Err(io::Error::new(io::ErrorKind::Other, "server sni is not spected")),
                };
                ServerAddr::SocketAddr {
                    addr: addr.clone(),
                    name: sni.clone(),
                }
            }
        };

        let config = Config::new(tuic_config)?;

        let (relay, req_tx) = relay_init(
            context,
            config.client_config,
            server_addr,
            connect_opts,
            config.token_digest,
            config.heartbeat_interval,
            config.reduce_rtt,
            config.udp_relay_mode,
            config.request_timeout,
            config.max_udp_relay_packet_size,
        )
        .await;

        let mut tuic_ctx = self.tuic_ctx.lock();
        if tuic_ctx.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "tuic: server {}: local relay task already runing",
                    self.server_config().addr()
                ),
            ));
        }

        *tuic_ctx = Some(TuicServerContext { req_tx });

        Ok(relay)
    }

    pub async fn tuic_send_req(&self, req: Request) -> io::Result<()> {
        let tuic_ctx = self.tuic_ctx.lock();
        let tuic_ctx = match tuic_ctx.as_ref() {
            Some(ctx) => ctx,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "tuic: server {}: send req: local relay task not runing",
                        self.server_config().addr()
                    ),
                ))
            }
        };

        tuic_ctx.req_tx.send(req).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("tuic: server {}: send req: {} ", self.server_config().addr(), e),
            )
        })?;

        Ok(())
    }
}
