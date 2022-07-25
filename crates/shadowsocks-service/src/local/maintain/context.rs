use hyper::{Body, Method, Request, Response, StatusCode};
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

    #[cfg(feature = "rate-limit")]
    async fn update_speed_limit(&self, req: Request<Body>) -> GenericResult<Response<Body>> {
        use shadowsocks::transport::{BoundWidth, RateLimiter};
        use std::str::FromStr;

        let mut rate_limit = None;

        let whole_body = hyper::body::to_bytes(req.into_body()).await?;
        if !whole_body.is_empty() {
            let str_speed_limit = std::str::from_utf8(&whole_body[..])?;

            let bound_width = BoundWidth::from_str(str_speed_limit)?;

            let quota = bound_width.to_quota_byte_per_second()?;

            let rate_limiter = RateLimiter::new(quota);

            log::trace!("maintain-service: speed-limit => {}({})", bound_width, str_speed_limit);

            rate_limit = Some(Arc::new(rate_limiter))
        } else {
            log::trace!("maintain-service: speed-limit => None");
        }

        self.service_context.set_rate_limiter(rate_limit);

        let response = Response::builder().status(StatusCode::OK).body(Body::empty())?;

        Ok(response)
    }
}
