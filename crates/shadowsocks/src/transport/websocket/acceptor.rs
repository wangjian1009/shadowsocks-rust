use std::collections::HashMap;

use async_trait::async_trait;
use std::{io, net::SocketAddr};
use tokio::io::AsyncWriteExt;

use super::{
    super::Acceptor, config::WebsocketPingType, create_websocket_key_response, parsed_http_data::ParsedHttpData,
    stream::WebsocketStream,
};

#[derive(Clone, Debug, PartialEq)]
pub struct WebSocketAcceptorConfig {
    pub matching_path: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub ping_type: WebsocketPingType,
}

impl Default for WebSocketAcceptorConfig {
    fn default() -> Self {
        Self {
            matching_path: None,
            matching_headers: None,
            ping_type: WebsocketPingType::Disabled,
        }
    }
}

pub struct WebSocketAcceptor<T: Acceptor> {
    matching_path: Option<String>,
    matching_headers: Option<HashMap<String, String>>,
    ping_type: WebsocketPingType,
    inner: T,
}

#[async_trait]
impl<T: Acceptor> Acceptor for WebSocketAcceptor<T> {
    type TS = WebsocketStream<T::TS>;

    async fn accept(&mut self) -> io::Result<(Self::TS, Option<SocketAddr>)> {
        let (mut server_stream, addr) = self.inner.accept().await?;

        let ParsedHttpData {
            mut first_line,
            headers: mut request_headers,
            line_reader,
        } = ParsedHttpData::parse(&mut server_stream).await?;
        let request_path = {
            if !first_line.ends_with(" HTTP/1.0") && !first_line.ends_with(" HTTP/1.1") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("invalid http request version: {}", first_line),
                ));
            }

            if !first_line.starts_with("GET ") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("invalid http request: {}", first_line),
                ));
            }

            // remove ' HTTP/1.x'
            first_line.truncate(first_line.len() - 9);

            // return the path after 'GET '
            first_line.split_off(4)
        };

        let websocket_key = request_headers
            .remove("sec-websocket-key")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "missing websocket key header"))?;

        if let Some(path) = self.matching_path.as_ref() {
            if path != &request_path {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No matching websocket targets",
                ));
            }
        }

        if let Some(headers) = self.matching_headers.as_ref() {
            for (header_key, header_val) in headers {
                if request_headers.get(header_key) != Some(header_val) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "No matching websocket targets",
                    ));
                }
            }
        }

        let websocket_key_response = create_websocket_key_response(websocket_key);

        let host_response_header = match request_headers.get("host") {
            Some(v) => format!("Host: {}\r\n", v),
            None => "".to_string(),
        };

        let websocket_version_response_header = match request_headers.get("sec-websocket_version") {
            Some(v) => format!("Sec-WebSocket-Version: {}\r\n", v),
            None => "".to_string(),
        };

        let http_response = format!(
            concat!(
                "HTTP/1.1 101 Switching Protocol\r\n",
                "{}",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "{}",
                "Sec-WebSocket-Accept: {}\r\n",
                "\r\n"
            ),
            host_response_header, websocket_version_response_header, websocket_key_response,
        );

        server_stream.write_all(http_response.as_bytes()).await?;

        let websocket_stream = WebsocketStream::new(
            server_stream,
            false,
            self.ping_type.clone(),
            line_reader.unparsed_data(),
        );
        Ok((websocket_stream, addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl<T: Acceptor> WebSocketAcceptor<T> {
    pub fn new(config: WebSocketAcceptorConfig, inner: T) -> Self {
        Self {
            matching_path: config.matching_path,
            matching_headers: config.matching_headers,
            ping_type: config.ping_type,
            inner,
        }
    }
}
