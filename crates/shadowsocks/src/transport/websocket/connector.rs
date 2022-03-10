use super::{
    super::{Connection, Connector},
    cvt_error,
    BinaryWsStream,
};
use crate::net::{ConnectOpts, Destination};
use async_trait::async_trait;
use std::io;
use tokio_tungstenite::{
    client_async,
    tungstenite::http::{StatusCode, Uri},
};

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
    type PR = T::PR;
    type PW = T::PW;
    type TS = BinaryWsStream<T::TS>;

    async fn connect(
        &self,
        destination: &Destination,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Connection<Self::TS, Self::PR, Self::PW>> {
        match self.inner.connect(destination, connect_opts).await? {
            Connection::Stream(stream) => {
                let (stream, resp) = client_async(&self.uri, stream).await.map_err(|e| cvt_error(e))?;
                if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                    return Err(cvt_error(format!("bad status: {}", resp.status())));
                }
                let stream = BinaryWsStream::new(stream);
                Ok(Connection::Stream(stream))
            }
            Connection::Packet { r, w, local_addr } => Ok(Connection::Packet { r, w, local_addr }),
        }
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
