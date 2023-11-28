use hyper::Server as HttpServer;
use shadowsocks::net::TcpListener;
use std::{io, net::SocketAddr};

use crate::local::{start_stat::StartStat, ServiceContext};

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type GenericResult<T> = std::result::Result<T, GenericError>;

mod context;
mod server;

use context::MaintainServerContext;

pub struct MaintainServer {
    context: MaintainServerContext,
    addr: SocketAddr,
}

impl MaintainServer {
    pub fn new(service_context: ServiceContext, addr: SocketAddr) -> MaintainServer {
        MaintainServer {
            context: MaintainServerContext::new(service_context),
            addr,
        }
    }

    pub async fn run(self, start_stat: StartStat) -> io::Result<()> {
        let listener = TcpListener::bind_with_opts(&self.addr, self.context.service_context.accept_opts()).await?;

        let server = match HttpServer::from_tcp(listener.into_inner().into_std()?) {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(err = ?err, "HttpServer::from_tcp error");
                return Err(io::Error::new(io::ErrorKind::Other, "HttpServer::from_tcp error"));
            }
        };

        let server = server.serve(server::MakeSvc {
            context: self.context.clone(),
        });

        tracing::info!("shadowsocks maintain server listening on {}", self.addr);
        start_stat.notify().await?;

        let cancel_waiter = self.context.service_context.cancel_waiter();
        tokio::select! {
            r = server => {
                // Run this server for... forever!
                if let Err(e) = r {
                    tracing::error!("maintain server error: {}", e);
                    Err(io::Error::new(io::ErrorKind::Other, e))
                } else {
                    Ok(())
                }
            }
            _ = cancel_waiter.wait() => {
                tracing::trace!("canceld");
                Ok(())
            }
        }
    }
}
