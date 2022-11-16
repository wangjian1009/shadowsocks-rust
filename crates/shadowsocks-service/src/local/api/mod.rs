use std::{future::Future, io, pin::Pin, sync::Arc, task};

use hyper::{
    client::Client,
    http::{self, uri::Uri},
    Body,
};
use tower::Service;
use tracing::{error, trace};

use shadowsocks::relay::socks5::Address;

use super::{http::ProxyHttpStream, loadbalancing::ServerIdent, net::AutoProxyClientStream, ServiceContext};

#[derive(Debug)]
pub enum ApiError {
    Other(Option<String>),
}

pub async fn request(
    request: http::Request<Body>,
    service_context: Arc<ServiceContext>,
    server: Arc<ServerIdent>,
) -> Result<http::Response<Body>, ApiError> {
    let connector = Connector {
        service_context,
        server,
    };

    let client = Client::builder().build(connector);

    client
        .request(request)
        .await
        .map_err(|e| ApiError::Other(Some(format!("{:?}", e))))
}

#[derive(Clone)]
struct Connector {
    service_context: Arc<ServiceContext>,
    server: Arc<ServerIdent>,
}

impl Service<Uri> for Connector {
    type Response = ProxyHttpStream;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
        task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let service_context = self.service_context.clone();
        let server = self.server.clone();

        Box::pin(async move {
            // 从URL获取目标地址
            let port = match uri.port() {
                Some(port) => port.as_u16(),
                None => match uri.scheme().map(|s| s.as_str()) {
                    None => 80,
                    Some("http") => 80,
                    Some("https") => 443,
                    Some(..) => {
                        error!(uri = ?uri, "target url no port");
                        return Err(io::Error::new(io::ErrorKind::Other, "target url no host"));
                    }
                },
            };

            let target_addr = match uri.host() {
                Some(host) => Address::parse_str_host(host, port),
                None => {
                    return Err(io::Error::new(io::ErrorKind::Other, "target url no host"));
                }
            };
            trace!(target_addr = ?target_addr);

            let stream = AutoProxyClientStream::connect_proxied(&service_context, &server, &target_addr).await?;

            Ok(ProxyHttpStream::connect_http(stream))
        })
    }
}
