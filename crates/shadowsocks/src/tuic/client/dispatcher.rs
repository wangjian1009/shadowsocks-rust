use std::io;
use std::{
    fmt::{self, Debug},
    future,
    sync::Arc,
};

use tokio::{
    sync::{mpsc::Sender, Notify, RwLock},
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

pub type ConfigProvider = Box<dyn Fn() -> io::Result<Config> + Send + Sync>;

pub struct Dispatcher {
    context: SharedContext,
    addr: ServerAddr,
    config_provider: ConfigProvider,
    connect_opts: ConnectOpts,
    runing: RwLock<Option<Runing>>,
}

impl Debug for Dispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tuic()")
    }
}

impl Dispatcher {
    pub fn new(
        context: SharedContext,
        addr: ServerAddr,
        config_provider: ConfigProvider,
        connect_opts: ConnectOpts,
    ) -> Self {
        Self {
            context,
            addr,
            config_provider,
            connect_opts,
            runing: RwLock::new(None),
        }
    }

    async fn run(self: Arc<Dispatcher>, close_notify: Option<Arc<Notify>>) -> io::Result<Runing> {
        let config = (*self.config_provider)()?;

        let (relay, req_tx) = relay_init(
            self.context.clone(),
            config.client_config.clone(),
            self.addr.clone(),
            self.connect_opts.clone(),
            config.token_digest,
            config.heartbeat_interval,
            config.reduce_rtt,
            config.udp_relay_mode,
            config.request_timeout,
            config.max_udp_relay_packet_size,
        )
        .await;

        let addr = self.addr.clone();
        let task = tokio::spawn(async move {
            log::info!("tuic: server {}: serve begin", addr);
            tokio::pin!(relay);

            let wait_close = async move {
                if let Some(close_notify) = close_notify {
                    close_notify.notified().await
                } else {
                    future::pending().await
                }
            };

            tokio::select! {
                r = relay => {
                    match r {
                        Ok(()) => log::info!("tuic: server {}: serve complete success", addr),
                        Err(err) => log::error!("tuic: server {}: serve complete error, {:?}", addr, err),
                    }
                }
                _r = wait_close => {
                    log::info!("tuic: server {}: serve closed by notify", addr);
                }
            }
        });
        Ok(Runing { task, req_tx })
    }

    pub async fn send_req(self: &Arc<Self>, req: Request, close_notify: Option<Arc<Notify>>) -> io::Result<()> {
        let left_req = self.tuic_try_send_req(req).await?;
        if left_req.is_none() {
            return Ok(());
        }

        self.start_svr(close_notify).await?;

        let left_req = self.tuic_try_send_req(left_req.unwrap()).await?;
        if left_req.is_none() {
            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("tuic: server {}: start server unknown error", self.addr),
        ))
    }

    async fn start_svr(self: &Arc<Self>, close_notify: Option<Arc<Notify>>) -> io::Result<()> {
        let mut runing = self.runing.write().await;

        if let Some(runing) = (*runing).as_mut() {
            if !runing.task.is_finished() {
                return Ok(());
            }
        }

        // log::error!("tuic: server start: sleep begin");
        // tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        // log::error!("tuic: server start: sleep end");

        *runing = Some(self.clone().run(close_notify).await?);

        Ok(())
    }

    async fn tuic_try_send_req(&self, req: Request) -> io::Result<Option<Request>> {
        let runing = self.runing.read().await;

        let runing = match *runing {
            Some(ref runing) => runing,
            None => return Ok(Some(req)),
        };

        if runing.task.is_finished() {
            return Ok(Some(req));
        }

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
