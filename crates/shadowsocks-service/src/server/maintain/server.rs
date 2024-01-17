use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, header, service::Service, Method, Request, Response, StatusCode};
use std::io::BufWriter;
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::io;

use super::ServerInfo;

#[derive(Clone)]
pub struct Svc {
    pub servers: Arc<Vec<ServerInfo>>,
}

impl Svc {
    pub async fn handle_request(
        servers: Arc<Vec<ServerInfo>>,
        req: Request<Incoming>,
    ) -> io::Result<Response<Full<Bytes>>> {
        let mut response = None;

        match (req.method(), req.uri().path()) {
            (&Method::GET, "/servers") => response = Some(Self::handle_servers(servers, req).await?),
            (&Method::GET, "/conns") => response = Some(Self::handle_conns(servers, req).await?),
            _ => {}
        };

        if response.is_none() {
            response = Some(Response::new(Full::new(Bytes::new())));
            if let Some(ref mut response) = response {
                *response.status_mut() = StatusCode::NOT_FOUND;
            }
        }

        Ok(response.unwrap())
    }

    async fn handle_servers(
        servers: Arc<Vec<ServerInfo>>,
        _req: Request<Incoming>,
    ) -> io::Result<Response<Full<Bytes>>> {
        let json = serde_json::to_string(servers.as_ref())?;
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    async fn handle_conns(servers: Arc<Vec<ServerInfo>>, _req: Request<Incoming>) -> io::Result<Response<Full<Bytes>>> {
        let wtr = BufWriter::new(vec![]);
        let mut wtr = csv::Writer::from_writer(wtr);

        wtr.write_record(["source", "remote", "conn-ms", "idle-ms", "tx", "rx"])?;

        for server in servers.as_ref() {
            let server_context = server.context.as_ref();
            let connection_stat = server_context.connection_stat_ref();

            let connections = connection_stat.query_in_connections().await;
            for connection in connections {
                let connection = connection.as_ref();
                let flow_state = &connection.flow;

                let remote_addr = match connection.remote_addr.lock().await.as_ref() {
                    None => "".to_string(),
                    Some(ref addr) => addr.to_string(),
                };

                wtr.write_record([
                    connection.source_addr.to_string().as_str(),
                    remote_addr.as_str(),
                    connection.creation_time.elapsed().as_micros().to_string().as_str(),
                    connection
                        .touch_time
                        .lock()
                        .await
                        .elapsed()
                        .as_micros()
                        .to_string()
                        .as_str(),
                    flow_state.tx().to_string().as_str(),
                    flow_state.rx().to_string().as_str(),
                ])?;
            }
        }

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/csv")
            .body(Full::new(Bytes::from(
                wtr.into_inner()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
                    .into_inner()?,
            )))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

impl Service<Request<Incoming>> for Svc {
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;
    type Response = Response<Full<Bytes>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let servers = self.servers.clone();
        Box::pin(async move { Self::handle_request(servers, req).await })
    }
}
