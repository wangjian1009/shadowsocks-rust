use super::{GenericResult, ServerInfo};
use hyper::{header, Body, Method, Request, Response, StatusCode};
use std::io::BufWriter;

pub struct MaintainServerContext {
    pub servers: Vec<ServerInfo>,
}

impl MaintainServerContext {
    pub async fn handle_request(&self, req: Request<Body>) -> GenericResult<Response<Body>> {
        let mut response = None;

        log::info!("xxxxx: request {:?}", req);

        match (req.method(), req.uri().path()) {
            (&Method::GET, "/servers") => response = Some(self.handle_servers(req).await?),
            (&Method::GET, "/conns") => response = Some(self.handle_conns(req).await?),
            _ => {}
        };

        if response.is_none() {
            response = Some(Response::new(Body::empty()));
            if let Some(ref mut response) = response {
                *response.status_mut() = StatusCode::NOT_FOUND;
            }
        }

        Ok(response.unwrap())
    }

    async fn handle_servers(&self, _req: Request<Body>) -> GenericResult<Response<Body>> {
        let json = serde_json::to_string(&self.servers)?;
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))?;
        Ok(response)
    }

    async fn handle_conns(&self, _req: Request<Body>) -> GenericResult<Response<Body>> {
        let wtr = BufWriter::new(vec![]);
        let mut wtr = csv::Writer::from_writer(wtr);

        wtr.write_record(&["source", "remote", "conn-ms", "idle-ms", "tx", "rx"])?;

        for ref server in &self.servers {
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

                wtr.write_record(&[
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

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/csv")
            .body(Body::from(wtr.into_inner()?.into_inner()?))?;

        Ok(response)
    }
}
