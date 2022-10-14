type GenericError = Box<dyn std::error::Error + Send + Sync>;
type GenericResult<T> = std::result::Result<T, GenericError>;

mod context;
mod data;
mod server;
use tracing::{error, info};

use hyper::Server as HttpServer;

use std::{io, net::SocketAddr, sync::Arc};

use shadowsocks::canceler::CancelWaiter;

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

    pub async fn run<'a, 'b>(self, cancel_waiter: CancelWaiter, addr: SocketAddr) -> io::Result<()> {
        let server = HttpServer::bind(&addr)
            .serve(server::MakeSvc {
                context: self.context.clone(),
            })
            .with_graceful_shutdown(async move { cancel_waiter.wait().await });

        info!("maintain server listening on {}", addr);

        if let Err(e) = server.await {
            error!(error = ?e, "maintain server exited with error");
            Err(io::Error::new(io::ErrorKind::Other, e))
        } else {
            info!("maintain server exited success");
            Ok(())
        }
    }
}
