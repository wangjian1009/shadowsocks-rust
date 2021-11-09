use super::{GenericResult, ServerInfo};
use hyper::{header, Body, Method, Request, Response, StatusCode};

pub struct MaintainServerContext {
    pub servers: Vec<ServerInfo>,
}

impl MaintainServerContext {
    pub async fn handle_request(&self, req: Request<Body>) -> GenericResult<Response<Body>> {
        let mut response = None;

        log::info!("xxxxx: request {:?}", req);

        match (req.method(), req.uri().path()) {
            (&Method::GET, "/servers") => response = Some(self.handle_servers(req).await?),
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
}
