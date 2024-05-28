use async_trait::async_trait;
use base64::Engine as _;
use std::collections::HashMap;
use std::io;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::{canceler::Canceler, net::ConnectOpts, ServerAddr};

use super::{
    super::Connector, config::WebsocketPingType, create_websocket_key_response, parsed_http_data::ParsedHttpData,
    stream::WebsocketStream,
};

#[derive(Clone, Debug, PartialEq)]
pub struct WebSocketConnectorConfig {
    pub uri: Url,
    pub headers: Option<HashMap<String, String>>,
    pub ping_type: WebsocketPingType,
}

impl Default for WebSocketConnectorConfig {
    fn default() -> Self {
        Self {
            uri: Url::parse("ws://dumy/").unwrap(),
            headers: None,
            ping_type: WebsocketPingType::PingFrame,
        }
    }
}

pub struct WebSocketConnector<T: Connector> {
    config: WebSocketConnectorConfig,
    inner: T,
}

impl<'a, T: Connector> WebSocketConnector<T> {
    pub fn new(config: WebSocketConnectorConfig, inner: T) -> io::Result<Self> {
        Ok(Self { config, inner })
    }
}

#[async_trait]
impl<T: Connector> Connector for WebSocketConnector<T> {
    type TS = WebsocketStream<T::TS>;

    async fn connect(
        &self,
        destination: &ServerAddr,
        connect_opts: &ConnectOpts,
        canceler: &Canceler,
    ) -> io::Result<Self::TS> {
        let mut client_stream = self.inner.connect(destination, connect_opts, canceler).await?;

        let authority = self.config.uri.authority();
        let host = authority
            .find('@')
            .map(|idx| authority.split_at(idx + 1).1)
            .unwrap_or_else(|| authority);

        let websocket_key = create_websocket_key();
        let mut http_request = String::with_capacity(1024);
        http_request.push_str("GET ");
        http_request.push_str(self.config.uri.path());
        http_request.push_str(" HTTP/1.1\r\n");
        http_request.push_str(concat!("Connection: Upgrade\r\n", "Upgrade: websocket\r\n",));
        http_request.push_str(format!("Host: {}\r\n", host).as_str());

        if let Some(ref headers) = self.config.headers {
            for (header_key, header_val) in headers {
                if header_key != "Host" {
                    http_request.push_str(header_key);
                    http_request.push_str(": ");
                    http_request.push_str(header_val);
                    http_request.push_str("\r\n");
                }
            }
        }

        http_request.push_str(concat!("Sec-WebSocket-Version: 13\r\n", "Sec-WebSocket-Key: "));
        http_request.push_str(&websocket_key);
        tracing::trace!("websocket handshake request\n{}", http_request);

        http_request.push_str("\r\n\r\n");

        let process = async {
            client_stream.write_all(&http_request.into_bytes()).await?;
            client_stream.flush().await?;
            ParsedHttpData::parse(&mut client_stream).await
        };

        let mut waiter = canceler.waiter();
        let ParsedHttpData {
            first_line,
            headers: response_headers,
            line_reader,
        } = tokio::select! {
            r = process => r?,
            _ = waiter.wait() => {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "canceled"));
            }
        };

        tracing::trace!(
            "websocket handshake response\n{}{}",
            first_line,
            response_headers
                .iter()
                .map(|(k, v)| format!("\n{}: {}", k, v))
                .collect::<String>()
        );

        if !first_line.starts_with("HTTP/1.1 101") && !first_line.starts_with("HTTP/1.0 101") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Bad websocket response: {}", first_line),
            ));
        }

        let websocket_key_response = response_headers
            .get("sec-websocket-accept")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "missing websocket key response header"))?;

        let expected_key_response = create_websocket_key_response(websocket_key);
        if websocket_key_response != &expected_key_response {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "incorrect websocket key response, expected {}, got {}",
                    expected_key_response, websocket_key_response
                ),
            ));
        }

        Ok(WebsocketStream::new(
            client_stream,
            true,
            self.config.ping_type.clone(),
            line_reader.unparsed_data(),
        ))
    }
}

fn create_websocket_key() -> String {
    let key: [u8; 16] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(key)
}
