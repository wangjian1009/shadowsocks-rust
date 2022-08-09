use hyper::{Body, Method, Request, Response, StatusCode};
use serde_json::json;
use std::sync::Arc;

use crate::local::ServiceContext;

use super::GenericResult;

pub struct MaintainServerContext {
    service_context: Arc<ServiceContext>,
}

impl MaintainServerContext {
    pub fn new(service_context: Arc<ServiceContext>) -> Self {
        Self { service_context }
    }

    pub async fn handle_request(&self, req: Request<Body>) -> GenericResult<Response<Body>> {
        let result = match (req.method(), req.uri().path()) {
            (&Method::GET, "/traffic") => self.query_traffic(req).await,
            #[cfg(feature = "rate-limit")]
            (&Method::POST, "/speed-limit") => self.update_speed_limit(req).await,
            _ => {
                log::error!(
                    "maintain-service: unknown request: {} {}",
                    req.method(),
                    req.uri().path()
                );

                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::NOT_FOUND;
                return Ok(response);
            }
        };

        match result {
            Ok(response) => Ok(response),
            Err(e) => {
                let m = e.to_string();
                let mut response = Response::new(Body::from(m));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Ok(response)
            }
        }
    }

    async fn query_traffic(&self, _req: Request<Body>) -> GenericResult<Response<Body>> {
        let flow_state = self.service_context.flow_stat();

        let response = json5::to_string(&json!({"tx": flow_state.tx(), "rx": flow_state.rx()}))?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(response.into_bytes()))?)
    }

    #[cfg(feature = "rate-limit")]
    async fn update_speed_limit(&self, req: Request<Body>) -> GenericResult<Response<Body>> {
        use shadowsocks::transport::BoundWidth;
        use std::str::FromStr;

        let mut bound_width = None;

        let whole_body = hyper::body::to_bytes(req.into_body()).await?;
        if !whole_body.is_empty() {
            let str_speed_limit = std::str::from_utf8(&whole_body[..])?;
            bound_width = Some(BoundWidth::from_str(str_speed_limit)?);
        }

        let rate_limiter = self.service_context.rate_limiter();

        let old_bound_width = rate_limiter.rate_limit();
        if old_bound_width != bound_width {
            log::info!(
                "maintain-service: speed-limit {:?} => {:?}",
                old_bound_width,
                bound_width
            );
            self.service_context.rate_limiter().set_rate_limit(bound_width)?;
        };

        let response = Response::builder().status(StatusCode::OK).body(Body::empty())?;

        Ok(response)
    }
}
