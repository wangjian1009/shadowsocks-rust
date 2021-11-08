use super::context::ServiceContext;
use hyper::{
    service::{make_service_fn, service_fn},
    Body,
    Request,
    Response,
    Server as HttpServer,
};
use log;
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc};

pub struct MaintainServer {
    server_contexts: Vec<Arc<ServiceContext>>,
}

impl MaintainServer {
    pub fn new(server_contexts: Vec<Arc<ServiceContext>>) -> MaintainServer {
        MaintainServer { server_contexts }
    }

    async fn hello_world(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
        Ok(Response::new("Hello, World".into()))
    }

    pub async fn run<'a, 'b>(self, addr: SocketAddr) -> io::Result<()> {
        let make_svc = make_service_fn(|_conn| async {
            // service_fn converts our function into a `Service`
            Ok::<_, Infallible>(service_fn(MaintainServer::hello_world))
        });

        let server = HttpServer::bind(&addr).serve(make_svc);

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
