use std::io;

pub use crate::relay::Address;

mod uuid;
pub use uuid::UUID;

pub mod protocol;

mod encoding;
pub use encoding::decode_request_header;

mod client_stream;
pub use client_stream::{ClientStream, ClientConfig};

mod packet;
pub use packet::{new_vless_packet_connection, VlessUdpReader, VlessUdpWriter};

fn new_error<T: ToString>(message: T) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("vless: {}", message.to_string()))
}

#[cfg(test)]
mod test_env;
