use std::io;

mod common;
pub use common::UUID;

mod inbound;
pub use inbound::InboundHandler;

pub mod protocol;
pub use protocol::Config;

mod encoding;
pub use encoding::decode_request_header;

mod client_stream;
pub use client_stream::ClientStream;

mod validator;

mod client_packet;
pub use client_packet::{new_vless_packet_connection, VlessUdpReader, VlessUdpWriter};

fn new_error<T: ToString>(message: T) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("vless: {}", message.to_string()))
}

#[cfg(test)]
mod test;
