use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, client::conn::http1, Request, Response};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tracing::{error, trace};

use shadowsocks::relay::socks5::Address;

use super::{http::ProxyHttpStream, loadbalancing::ServerIdent, net::AutoProxyClientStream, ServiceContext};

#[derive(Debug)]
pub enum ApiError {
    Other(Option<String>),
}

pub async fn request(
    request: Request<Full<Bytes>>,
    service_context: Arc<ServiceContext>,
    server: Arc<ServerIdent>,
) -> Result<Response<Incoming>, ApiError> {
    // 从URL获取目标地址
    let port = match request.uri().port() {
        Some(port) => port.as_u16(),
        None => match request.uri().scheme().map(|s| s.as_str()) {
            None => 80,
            Some("http") => 80,
            Some("https") => 443,
            Some(..) => {
                error!(uri = ?request.uri(), "target url no port");
                return Err(ApiError::Other(Some("target url no port".to_string())));
            }
        },
    };

    let target_addr = match request.uri().host() {
        Some(host) => Address::parse_str_host(host, port),
        None => {
            return Err(ApiError::Other(Some("target url no host".to_string())));
        }
    };
    trace!(target_addr = ?target_addr);

    let stream = AutoProxyClientStream::connect_proxied(&service_context, &server, &target_addr)
        .await
        .map_err(|e| ApiError::Other(Some(format!("{:?}", e))))?;

    let stream = ProxyHttpStream::connect_http(stream);

    let io = TokioIo::new(stream);

    let (mut sender, conn) = http1::handshake(io)
        .await
        .map_err(|e| ApiError::Other(Some(format!("{:?}", e))))?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    sender
        .send_request(request)
        .await
        .map_err(|e| ApiError::Other(Some(format!("{:?}", e))))
}
