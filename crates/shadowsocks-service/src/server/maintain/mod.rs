use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use std::{io, net::SocketAddr, sync::Arc};

use shadowsocks::canceler::CancelWaiter;
use shadowsocks::net::{AcceptOpts, TcpListener};

mod data;
mod server;
use tracing::{error, info, Instrument};

use server::Svc;

pub use data::ServerInfo;

pub struct MaintainServer {
    servers: Vec<ServerInfo>,
}

impl MaintainServer {
    pub fn new(servers: Vec<ServerInfo>) -> MaintainServer {
        MaintainServer { servers }
    }

    pub async fn run<'a, 'b>(self, mut cancel_waiter: CancelWaiter, addr: SocketAddr) -> io::Result<()> {
        let MaintainServer { servers } = self;
        let listener = TcpListener::bind_with_opts(&addr, AcceptOpts::default()).await?;

        info!("maintain server listening on {}", addr);

        let svc = Svc {
            servers: Arc::new(servers),
        };

        tokio::select! {
            r = Self::serve(svc, listener) => {
                if let Err(e) = r {
                    error!(error = ?e, "maintain server exited with error");
                    Err(io::Error::new(io::ErrorKind::Other, e))
                } else {
                    info!("maintain server exited success");
                    Ok(())
                }
            }
            _ = cancel_waiter.wait() => {
                tracing::trace!("canceld");
                Ok(())
            }
        }
    }

    async fn serve(svc: Svc, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;

            // Use an adapter to access something implementing `tokio::io` traits as if they implement
            // `hyper::rt` IO traits.
            let io = TokioIo::new(stream);
            let svc = svc.clone();

            // Spawn a tokio task to serve multiple connections concurrently
            tokio::task::spawn(async move {
                // Finally, we bind the incoming connection to our `hello` service
                if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, svc)
                .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            }.in_current_span());
        }
    }
}
