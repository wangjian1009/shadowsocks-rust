use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::Service, Method, Request, Response, StatusCode};
use serde_json::json;
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::io;

use crate::local::ServiceContext;

#[derive(Clone)]
pub struct Svc {
    context: Arc<ServiceContext>,
}

impl Svc {
    pub fn new(context: Arc<ServiceContext>) -> Self {
        Self { context }
    }

    pub async fn handle_request(
        context: Arc<ServiceContext>,
        req: Request<Incoming>,
    ) -> io::Result<Response<Full<Bytes>>> {
        let result = match (req.method(), req.uri().path()) {
            (&Method::GET, "/traffic") => Self::query_traffic(context, req).await,
            #[cfg(feature = "local-signed-info")]
            (&Method::GET, "/android/validate") => Self::android_validate(context, req).await,
            #[cfg(feature = "rate-limit")]
            (&Method::POST, "/speed-limit") => Self::update_speed_limit(context, req).await,
            #[cfg(feature = "rate-limit")]
            (&Method::GET, "/speed-limit") => Self::query_speed_limit(context, req).await,
            _ => {
                tracing::error!(
                    "maintain-service: unknown request: {} {}",
                    req.method(),
                    req.uri().path()
                );

                let mut response = Response::new(Full::new(Bytes::new()));
                *response.status_mut() = StatusCode::NOT_FOUND;
                return Ok(response);
            }
        };

        match result {
            Ok(response) => Ok(response),
            Err(e) => {
                let m = e.to_string();
                let mut response = Response::new(Full::new(Bytes::from(m)));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Ok(response)
            }
        }
    }

    async fn query_traffic(context: Arc<ServiceContext>, _req: Request<Incoming>) -> io::Result<Response<Full<Bytes>>> {
        let flow_state = context.flow_stat();

        let response = json5::to_string(&json!({"tx": flow_state.tx(), "rx": flow_state.rx()}))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(response.into_bytes())))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    #[cfg(feature = "rate-limit")]
    async fn query_speed_limit(
        context: Arc<ServiceContext>,
        _req: Request<Incoming>,
    ) -> io::Result<Response<Full<Bytes>>> {
        let rate_limiter = context.rate_limiter();

        let bound_width = rate_limiter.rate_limit();

        let response = json5::to_string(&json!(
            {"rate-limit":  bound_width.map(|s| format!("{:?}", s)).unwrap_or_else(|| "0".to_string())
        }))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(response)))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    #[cfg(feature = "rate-limit")]
    async fn update_speed_limit(
        context: Arc<ServiceContext>,
        req: Request<Incoming>,
    ) -> io::Result<Response<Full<Bytes>>> {
        use shadowsocks::transport::BoundWidth;
        use std::str::FromStr;

        let mut bound_width = None;

        let whole_body = req
            .collect()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            .to_bytes();
        if !whole_body.is_empty() {
            let str_speed_limit =
                std::str::from_utf8(&whole_body[..]).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            if str_speed_limit != "0" {
                bound_width =
                    Some(BoundWidth::from_str(str_speed_limit).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?);
            }
        }

        let rate_limiter = context.rate_limiter();

        let old_bound_width = rate_limiter.rate_limit();
        let r = if old_bound_width != bound_width {
            tracing::info!(
                "maintain-service: speed-limit {:?} => {:?}",
                old_bound_width,
                bound_width
            );
            context.rate_limiter().set_rate_limit(bound_width)
        } else {
            tracing::info!(
                "maintain-service: speed-limit {:?} => {:?} not changed",
                old_bound_width,
                bound_width
            );
            Ok(())
        };

        tracing::info!("maintain-service: current speed-limit = {:?}", context.rate_limiter());

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

        Response::builder()
            .status(response_code)
            .body(Full::new(Bytes::new()))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    #[cfg(feature = "local-signed-info")]
    async fn android_validate(
        _context: Arc<ServiceContext>,
        _req: Request<Incoming>,
    ) -> io::Result<Response<Full<Bytes>>> {
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
        }))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(response.into_bytes())))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

impl Service<Request<Incoming>> for Svc {
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;
    type Response = Response<Full<Bytes>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let context = self.context.clone();
        Box::pin(async move { Self::handle_request(context, req).await })
    }
}
