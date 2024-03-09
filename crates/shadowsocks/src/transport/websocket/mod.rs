pub mod acceptor;
pub mod connector;
mod stream;
mod config;
mod parsed_http_data;
use base64::Engine as _;
use sha1::{Digest, Sha1};

pub use config::WebsocketPingType;
pub use acceptor::{WebSocketAcceptor, WebSocketAcceptorConfig};
pub use connector::{WebSocketConnector, WebSocketConnectorConfig};

fn create_websocket_key_response(mut key: String) -> String {
    // after some testing - the sha1 crate seems faster than sha-1.
    key.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

    let mut hasher = Sha1::new();
    hasher.update(key.into_bytes());
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(hash)
}
