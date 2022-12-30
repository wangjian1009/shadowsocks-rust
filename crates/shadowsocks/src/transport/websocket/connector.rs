use async_trait::async_trait;
use std::io;
use tokio_tungstenite::{
    client_async,
    tungstenite::http::{StatusCode, Uri},
};

use crate::{net::ConnectOpts, ServerAddr};

use super::{super::Connector, cvt_error, BinaryWsStream};

#[derive(Clone, Debug, PartialEq)]
pub struct WebSocketConnectorConfig {
    pub path: String,
    pub host: String,
}

pub struct WebSocketConnector<T: Connector> {
    uri: Uri,
    inner: T,
}

#[async_trait]
impl<T: Connector> Connector for WebSocketConnector<T> {
    type TS = BinaryWsStream<T::TS>;

    async fn connect(&self, destination: &ServerAddr, connect_opts: &ConnectOpts) -> io::Result<Self::TS> {
        let stream = self.inner.connect(destination, connect_opts).await?;
        let (stream, resp) = client_async(&self.uri, stream).await.map_err(cvt_error)?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(cvt_error(format!("bad status: {}", resp.status())));
        }
        let stream = BinaryWsStream::new(stream);
        Ok(stream)
    }
}

impl<'a, T: Connector> WebSocketConnector<T> {
    pub fn new(config: &'a WebSocketConnectorConfig, inner: T) -> io::Result<Self> {
        let uri = Uri::builder()
            .scheme("ws")
            .authority(config.host.clone())
            .path_and_query(config.path.clone())
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("WebSocket build uril fail: {:?}", e)))?;
        Ok(Self { inner, uri })
    }
}
