use std::io;

pub mod protocol;

mod client_packet;
pub use client_packet::{new_trojan_packet_connection, TrojanUdpReader, TrojanUdpWriter};

mod client_stream;
pub use client_stream::ClientStream;

fn new_error<T: ToString>(message: T) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("trojan: {}", message.to_string()))
}
