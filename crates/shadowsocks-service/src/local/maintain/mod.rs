use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use shadowsocks::net::TcpListener;
use std::{io, net::SocketAddr, sync::Arc};

use crate::local::{start_stat::StartStat, ServiceContext};

mod server;

use server::Svc;

pub struct MaintainServer {
    service_context: ServiceContext,
    addr: SocketAddr,
}

impl MaintainServer {
    pub fn new(service_context: ServiceContext, addr: SocketAddr) -> MaintainServer {
        MaintainServer { service_context, addr }
    }

    pub async fn run(self, start_stat: StartStat) -> io::Result<()> {
        let MaintainServer { service_context, addr } = self;

        let listener = TcpListener::bind_with_opts(&addr, service_context.accept_opts()).await?;

        tracing::info!("shadowsocks maintain server listening on {}", self.addr);
        start_stat.notify().await?;

        let cancel_waiter = service_context.cancel_waiter();

        let svc = Svc::new(Arc::new(service_context));

        tokio::select! {
            r = Self::serve(svc, listener) => {
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
            });
        }
    }
}
