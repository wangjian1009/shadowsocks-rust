use hyper::Server as HttpServer;
use std::{io, net::SocketAddr, sync::Arc};

use crate::local::ServiceContext;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type GenericResult<T> = std::result::Result<T, GenericError>;

mod context;
mod server;

use context::MaintainServerContext;

pub struct MaintainServer {
    context: Arc<MaintainServerContext>,
}

impl MaintainServer {
    pub fn new(service_context: Arc<ServiceContext>) -> MaintainServer {
        MaintainServer {
            context: Arc::new(MaintainServerContext::new(service_context)),
        }
    }

    pub async fn run(self, addr: SocketAddr) -> io::Result<()> {
        let server = HttpServer::bind(&addr).serve(server::MakeSvc {
            context: self.context.clone(),
        });

        log::info!("shadowsocks maintain server listening on {}", addr);

        // Run this server for... forever!
        if let Err(e) = server.await {
            log::error!("maintain server error: {}", e);
            Err(io::Error::new(io::ErrorKind::Other, e))
        } else {
            Ok(())
        }
    }
}
