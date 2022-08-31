use std::io;
use std::{
    fmt::{self, Debug},
    sync::Arc,
};

use tokio::{
    sync::{mpsc::Sender, RwLock},
    task::JoinHandle,
};

use crate::context::SharedContext;
use crate::net::ConnectOpts;

use super::{relay_init, Config, Request, ServerAddr};

struct Runing {
    task: JoinHandle<()>,
    req_tx: Sender<Request>,
}

impl Drop for Runing {
    fn drop(&mut self) {
        self.task.abort()
    }
}

pub struct Dispatcher {
    context: SharedContext,
    addr: ServerAddr,
    config: Config,
    connect_opts: ConnectOpts,
    runing: RwLock<Option<Runing>>,
}

impl Debug for Dispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tuic()")
    }
}

impl Dispatcher {
    pub fn new(context: SharedContext, addr: ServerAddr, config: Config, connect_opts: ConnectOpts) -> Self {
        Self {
            context,
            addr,
            config,
            connect_opts,
            runing: RwLock::new(None),
        }
    }

    async fn run(self: Arc<Dispatcher>) -> io::Result<Runing> {
        // let server_addr = match addr {
        //     ServerAddr::DomainName(domain, port) => TuicServerAddr::DomainAddr {
        //         domain: domain.clone(),
        //         port: port.clone(),
        //     },
        //     ServerAddr::SocketAddr(addr) => {
        //         let sni = match self.config.sni.as_ref() {
        //             Some(sni) => sni,
        //             None => return Err(io::Error::new(io::ErrorKind::Other, "server sni is not spected")),
        //         };
        //         TuicServerAddr::SocketAddr {
        //             addr: addr.clone(),
        //             name: sni.clone(),
        //         }
        //     }
        // };

        let (relay, req_tx) = relay_init(
            self.context.clone(),
            self.config.client_config.clone(),
            self.addr.clone(),
            self.connect_opts.clone(),
            self.config.token_digest,
            self.config.heartbeat_interval,
            self.config.reduce_rtt,
            self.config.udp_relay_mode,
            self.config.request_timeout,
            self.config.max_udp_relay_packet_size,
        )
        .await;

        let addr = self.addr.clone();
        let task = tokio::spawn(async move {
            log::info!("tuic: server {}: serve begin", addr);
            tokio::pin!(relay);
            match relay.await {
                Ok(()) => log::info!("tuic: server {}: serve complete success", addr),
                Err(err) => log::error!("tuic: server {}: serve complete error, {:?}", addr, err),
            }
        });
        Ok(Runing { task, req_tx })
    }

    pub async fn send_req(self: &Arc<Self>, req: Request) -> io::Result<()> {
        let left_req = self.tuic_try_send_req(req).await?;
        if left_req.is_none() {
            return Ok(());
        }

        self.start_svr().await?;

        let left_req = self.tuic_try_send_req(left_req.unwrap()).await?;
        if left_req.is_none() {
            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("tuic: server {}: start server unknown error", self.addr),
        ))
    }

    async fn start_svr(self: &Arc<Self>) -> io::Result<()> {
        let mut runing = self.runing.write().await;

        if runing.is_some() {
            return Ok(());
        }

        // log::error!("tuic: server start: sleep begin");
        // tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        // log::error!("tuic: server start: sleep end");

        *runing = Some(self.clone().run().await?);

        Ok(())
    }

    async fn tuic_try_send_req(&self, req: Request) -> io::Result<Option<Request>> {
        let runing = self.runing.read().await;

        let runing = match *runing {
            Some(ref runing) => runing,
            None => return Ok(Some(req)),
        };

        log::error!("tuic: server {}: ==> {} ", self.addr, req);
        runing.req_tx.send(req).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("tuic: server {}: send req: {} ", self.addr, e),
            )
        })?;

        return Ok(None);
    }
}
