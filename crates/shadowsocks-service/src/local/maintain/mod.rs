use hyper::Server as HttpServer;
use std::{io, net::SocketAddr};

use crate::local::ServiceContext;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type GenericResult<T> = std::result::Result<T, GenericError>;

mod context;
mod server;

use context::MaintainServerContext;

pub struct MaintainServer {
    context: MaintainServerContext,
}

impl MaintainServer {
    pub fn new(service_context: ServiceContext) -> MaintainServer {
        MaintainServer {
            context: MaintainServerContext::new(service_context),
        }
    }

    pub async fn run(self, addr: SocketAddr) -> io::Result<()> {
        let server = HttpServer::bind(&addr).serve(server::MakeSvc {
            context: self.context.clone(),
        });

        tracing::info!("shadowsocks maintain server listening on {}", addr);

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
