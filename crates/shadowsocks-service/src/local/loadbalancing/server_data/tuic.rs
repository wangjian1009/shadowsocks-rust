use shadowsocks::{
    config::TuicConfig,
    tuic::client::{relay_init, Config, Request, ServerAddr},
};
use std::io;
use std::{fmt, sync::Arc};

use tokio::{
    sync::{mpsc::Sender, RwLock},
    task::JoinHandle,
};

use super::*;

use crate::local::context::ServiceContext;

pub struct TuicServerRuning {
    task: JoinHandle<()>,
    req_tx: Sender<Request>,
}

impl Drop for TuicServerRuning {
    fn drop(&mut self) {
        self.task.abort()
    }
}

pub struct TuicServerContext {
    context: Arc<ServiceContext>,
    tuic_config: TuicConfig,
    runing: RwLock<Option<TuicServerRuning>>,
}

impl Debug for TuicServerContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tuic()")
    }
}

impl TuicServerContext {
    pub fn new(context: Arc<ServiceContext>, tuic_config: TuicConfig) -> Self {
        Self {
            context,
            tuic_config,
            runing: RwLock::new(None),
        }
    }

    async fn run(self: Arc<TuicServerContext>, addr: &shadowsocks::ServerAddr) -> io::Result<TuicServerRuning> {
        let tuic_config = match &self.tuic_config {
            TuicConfig::Client(c) => c,
            TuicConfig::Server(..) => unreachable!(),
        };

        let server_addr = match addr {
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
            self.context.context(),
            config.client_config,
            server_addr,
            self.context.connect_opts_ref().clone(),
            config.token_digest,
            config.heartbeat_interval,
            config.reduce_rtt,
            config.udp_relay_mode,
            config.request_timeout,
            config.max_udp_relay_packet_size,
        )
        .await;

        let addr = addr.clone();
        let task = tokio::spawn(async move {
            log::info!("tuic: server {}: serve begin", addr);
            tokio::pin!(relay);
            match relay.await {
                Ok(()) => log::info!("tuic: server {}: serve complete success", addr),
                Err(err) => log::error!("tuic: server {}: serve complete error, {:?}", addr, err),
            }
        });
        Ok(TuicServerRuning { task, req_tx })
    }
}

impl ServerIdent {
    pub async fn tuic_send_req(&self, req: Request) -> io::Result<()> {
        let left_req = self.tuic_try_send_req(req).await?;
        if left_req.is_none() {
            return Ok(());
        }

        self.tuic_start_svr().await?;

        let left_req = self.tuic_try_send_req(left_req.unwrap()).await?;
        if left_req.is_none() {
            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "tuic: server {}: start server unknown error",
                self.server_config().addr()
            ),
        ))
    }

    async fn tuic_start_svr(&self) -> io::Result<()> {
        let tuic_ctx = self.tuic_ctx.as_ref().unwrap();
        let mut runing = tuic_ctx.runing.write().await;

        if runing.is_some() {
            return Ok(());
        }

        log::error!("tuic: server start: sleep begin");
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        log::error!("tuic: server start: sleep end");

        *runing = Some(tuic_ctx.clone().run(self.server_config().addr()).await?);

        Ok(())
    }

    async fn tuic_try_send_req(&self, req: Request) -> io::Result<Option<Request>> {
        let runing = self.tuic_ctx.as_ref().unwrap().runing.read().await;

        let runing = match *runing {
            Some(ref runing) => runing,
            None => return Ok(Some(req)),
        };

        log::error!("tuic: server {}: ==> {} ", self.server_config().addr(), req);
        runing.req_tx.send(req).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("tuic: server {}: send req: {} ", self.server_config().addr(), e),
            )
        })?;

        return Ok(None);
    }
}
