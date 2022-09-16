use std::{io, net::SocketAddr};

use async_trait::async_trait;
use bytes::Bytes;

mod certificate;
mod config;
mod connection;
mod server;

pub use config::{Config, RawConfig};
pub use server::Server;

pub use super::protocol::Address;

#[async_trait]
pub trait UdpSocket: Sync + Send {
    async fn recv_from(&self) -> io::Result<(Bytes, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], addr: Address) -> io::Result<()>;
}

#[async_trait]
pub trait UdpSocketCreator: Sync + Send {
    async fn create_outbound_udp_socket(&self, assoc_id: u32, peer_addr: SocketAddr) -> io::Result<Box<dyn UdpSocket>>;
}
