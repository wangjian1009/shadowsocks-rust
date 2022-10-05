type GenericError = Box<dyn std::error::Error + Send + Sync>;
type GenericResult<T> = std::result::Result<T, GenericError>;

mod context;
mod data;
mod server;

use hyper::Server as HttpServer;

use std::{io, net::SocketAddr, sync::Arc};

use context::MaintainServerContext;
pub use data::ServerInfo;

pub struct MaintainServer {
    context: Arc<MaintainServerContext>,
}

impl MaintainServer {
    pub fn new(servers: Vec<ServerInfo>) -> MaintainServer {
        MaintainServer {
            context: Arc::new(MaintainServerContext { servers }),
        }
    }

    pub async fn run<'a, 'b>(self, addr: SocketAddr) -> io::Result<()> {
        let server = HttpServer::bind(&addr).serve(server::MakeSvc {
            context: self.context.clone(),
        });

        tracing::info!("shadowsocks maintain server listening on {}", addr);

        // Run this server for... forever!
        if let Err(e) = server.await {
            tracing::error!("maintain server error: {}", e);
            Err(io::Error::new(io::ErrorKind::Other, e))
        } else {
            Ok(())
        }
    }
}
