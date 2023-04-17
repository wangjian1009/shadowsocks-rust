use hyper::{Body, Method, Request, Response, StatusCode};
use serde_json::json;

use crate::local::ServiceContext;

use super::GenericResult;

#[derive(Clone)]
pub(super) struct MaintainServerContext {
    pub(super) service_context: ServiceContext,
}

impl MaintainServerContext {
    pub fn new(service_context: ServiceContext) -> Self {
        Self { service_context }
    }

    pub async fn handle_request(&self, req: Request<Body>) -> GenericResult<Response<Body>> {
        let result = match (req.method(), req.uri().path()) {
            (&Method::GET, "/traffic") => self.query_traffic(req).await,
            #[cfg(feature = "local-signed-info")]
            (&Method::GET, "/android/validate") => self.android_validate(req).await,
            #[cfg(feature = "rate-limit")]
            (&Method::POST, "/speed-limit") => self.update_speed_limit(req).await,
            _ => {
                tracing::error!(
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
            if str_speed_limit != "0" {
                bound_width = Some(BoundWidth::from_str(str_speed_limit)?);
            }
        }

        let rate_limiter = self.service_context.rate_limiter();

        let old_bound_width = rate_limiter.rate_limit();
        let r = if old_bound_width != bound_width {
            tracing::info!(
                "maintain-service: speed-limit {:?} => {:?}",
                old_bound_width,
                bound_width
            );
            self.service_context.rate_limiter().set_rate_limit(bound_width)
        } else {
            tracing::info!(
                "maintain-service: speed-limit {:?} => {:?} not changed",
                old_bound_width,
                bound_width
            );
            Ok(())
        };

        tracing::info!(
            "maintain-service: current speed-limit = {:?}",
            self.service_context.rate_limiter()
        );

        #[allow(unused_mut)]
        let mut response_code = if r.is_ok() {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        };

        #[cfg(feature = "local-android-protect")]
        if response_code == StatusCode::OK {
            use crate::local::android;

            let check_result = android::validate_sign();
            if let Some(error) = check_result.error {
                response_code = StatusCode::from_u16(300 + error.code()).unwrap();
            } else if let Some(_error) = check_result.path_error {
                response_code = StatusCode::from_u16(201).unwrap();
            }
        }

        let response = Response::builder().status(response_code).body(Body::empty())?;

        Ok(response)
    }
}

impl MaintainServerContext {
    #[cfg(feature = "local-signed-info")]
    async fn android_validate(&self, _req: Request<Body>) -> GenericResult<Response<Body>> {
        use crate::local::android;

        let validate_result = android::validate_sign();

        let response = json5::to_string(&json!(
        {"signedDataFile": validate_result.signed_data_file.map(|v| {
            let parts: Vec<&str> = v.split('/').collect();
            parts.last().map(|v| v.to_string())
        }),
         "sha1Fingerprint": validate_result.sha1_fingerprint.map(|e| {
             e.iter().map(|e| format!("{:X}", e)).collect::<Vec<String>>().join(":")
         }),
         "error": validate_result.error.as_ref().map(|e| format!("{}", e)),
         "errorDetail": validate_result.error.as_ref().map(|e| format!("{:?}", e)),
         "pathError": validate_result.path_error.as_ref().map(|e| format!("{}", e)),
        }))?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(response.into_bytes()))?)
    }
}
