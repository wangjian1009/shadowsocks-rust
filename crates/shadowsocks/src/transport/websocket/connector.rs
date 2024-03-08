use async_trait::async_trait;
use base64::Engine as _;
use std::collections::HashMap;
use std::io;
use tokio_tungstenite::{
    client_async,
    tungstenite::http::{Method, Request, StatusCode, Uri},
};

use crate::{net::ConnectOpts, ServerAddr};

use super::{super::Connector, cvt_error, BinaryWsStream};

#[derive(Clone, Debug, PartialEq)]
pub struct WebSocketConnectorConfig {
    pub uri: Uri,
    pub headers: Option<HashMap<String, String>>,
}

pub struct WebSocketConnector<T: Connector> {
    config: WebSocketConnectorConfig,
    inner: T,
}

#[async_trait]
impl<T: Connector> Connector for WebSocketConnector<T> {
    type TS = BinaryWsStream<T::TS>;

    async fn connect(&self, destination: &ServerAddr, connect_opts: &ConnectOpts) -> io::Result<Self::TS> {
        let stream = self.inner.connect(destination, connect_opts).await?;
        let req = self.req()?;
        tracing::error!("xxxxx: connect: req={:?}", req);
        let (stream, resp) = match client_async(req, stream).await.map_err(cvt_error) {
            Ok(r) => r,
            Err(err) => {
                tracing::error!(err = ?err, "websocket handshake error");
                return Err(err);
            }
        };
        tracing::error!("xxxxx: connect: rsp={:?}", resp);
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(cvt_error(format!("bad status: {}", resp.status())));
        }
        let stream = BinaryWsStream::new(stream);
        Ok(stream)
    }
}

impl<'a, T: Connector> WebSocketConnector<T> {
    pub fn new(config: &'a WebSocketConnectorConfig, inner: T) -> io::Result<Self> {
        Ok(Self {
            inner,
            config: config.clone(),
        })
    }

    fn req(&self) -> io::Result<Request<()>> {
        let authority = self.config.uri.authority().unwrap().as_str();
        let host = authority
            .find('@')
            .map(|idx| authority.split_at(idx + 1).1)
            .unwrap_or_else(|| authority);
        let mut request = Request::builder()
            .method(Method::GET)
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .uri(self.config.uri.clone());
        if let Some(headers) = self.config.headers.as_ref() {
            for (k, v) in headers.iter() {
                if k != "Host" {
                    request = request.header(k.as_str(), v.as_str());
                }
            }
        }
        // if self.max_early_data > 0 {
        //     // we will replace this field later
        //     request = request.header(self.early_data_header_name.as_str(), "s");
        // }
        request.body(()).map_err(cvt_error)
    }
}

/// Generate a random key for the `Sec-WebSocket-Key` header.
pub fn generate_key() -> String {
    // a base64-encoded (see Section 4 of [RFC4648]) value that,
    // when decoded, is 16 bytes in length (RFC 6455)
    let r: [u8; 16] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(r)
}
