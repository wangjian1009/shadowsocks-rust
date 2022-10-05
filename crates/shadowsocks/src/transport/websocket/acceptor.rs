use crate::ServerAddr;

use super::{
    super::{Acceptor, Connection},
    cvt_error, BinaryWsStream,
};
use async_trait::async_trait;
use std::{io, net::SocketAddr};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{Callback, ErrorResponse, Request, Response},
        http::StatusCode,
    },
};
use tracing::error;

#[derive(Clone, Debug, PartialEq)]
pub struct WebSocketAcceptorConfig {
    pub path: String,
}

struct WebSocketCallback {
    path: String,
}

impl Callback for WebSocketCallback {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        if request.uri().to_string() != self.path {
            let mut resp = ErrorResponse::new(None);
            *resp.status_mut() = StatusCode::NOT_FOUND;
            error!("invalid websocket path: {}, expected: {}", request.uri(), self.path);
            Err(resp)
        } else {
            Ok(response)
        }
    }
}

pub struct WebSocketAcceptor<T: Acceptor> {
    path: String,
    inner: T,
}

#[async_trait]
impl<T: Acceptor> Acceptor for WebSocketAcceptor<T> {
    type PR = T::PR;
    type PW = T::PW;
    type TS = BinaryWsStream<T::TS>;

    async fn accept(&mut self) -> io::Result<(Connection<Self::TS, Self::PR, Self::PW>, Option<ServerAddr>)> {
        let (stream, addr) = self.inner.accept().await?;
        match stream {
            Connection::Stream(stream) => {
                let stream = accept_hdr_async_with_config(
                    stream,
                    WebSocketCallback {
                        path: self.path.clone(),
                    },
                    None,
                )
                .await
                .map_err(|e| cvt_error(e))?;
                let stream = BinaryWsStream::new(stream);
                Ok((Connection::Stream(stream), addr))
            }
            Connection::Packet { r, w, local_addr } => Ok((Connection::Packet { r, w, local_addr }, addr)),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl<T: Acceptor> WebSocketAcceptor<T> {
    pub fn new(config: &WebSocketAcceptorConfig, inner: T) -> Self {
        Self {
            inner,
            path: config.path.clone(),
        }
    }
}
