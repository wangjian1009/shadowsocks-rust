use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;

use crate::net::FlowStat;

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
pub trait ServerPolicy: Sync + Send {
    async fn create_outbound_udp_socket(&self, assoc_id: u32, peer_addr: SocketAddr) -> io::Result<Box<dyn UdpSocket>>;
    fn create_connection_flow_state(&self) -> Option<Arc<FlowStat>>;

    fn connection_check_process_local(&self, target_addr: &Address) -> bool;
    async fn connection_process_local(
        &self,
        peer_addr: &SocketAddr,
        target_addr: Address,
        r: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        w: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    ) -> io::Result<()>;

    #[cfg(feature = "rate-limit")]
    fn create_connection_rate_limit(&self) -> io::Result<Option<crate::transport::RateLimiter>>;

    async fn check_outbound_blocked(&self, addr: &Address) -> bool;
    fn check_client_blocked(&self, addr: &SocketAddr) -> bool;
}
