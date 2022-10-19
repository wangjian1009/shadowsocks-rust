use async_trait::async_trait;
use bytes::Bytes;
use std::{io, net::SocketAddr, sync::Arc};

use crate::{
    net::{FlowStat, TcpStream},
    timeout::TimeoutTicker,
    ServerAddr,
};

use tokio::io::{AsyncRead, AsyncWrite};

#[async_trait]
pub trait LocalProcessor: Sync + Send {
    async fn process(
        &self,
        r: Box<dyn AsyncRead + Send + Unpin>,
        w: Box<dyn AsyncWrite + Send + Unpin>,
        timeout_ticker: Option<TimeoutTicker>,
    ) -> io::Result<()>;
}

#[async_trait]
pub trait ConnectionGuard: Sync + Send {}

pub enum StreamAction {
    Remote {
        connection_guard: Box<dyn ConnectionGuard>,
        #[cfg(feature = "rate-limit")]
        rate_limit: Option<Arc<crate::transport::RateLimiter>>,
    },
    Local {
        processor: Box<dyn LocalProcessor>,
    },
    OutboundBlocked,
    ClientBlocked,
    ConnectionLimited,
}

pub enum PacketAction {
    Remote,
    OutboundBlocked,
    ClientBlocked,
}

#[async_trait]
pub trait UdpSocket: Sync + Send {
    async fn recv_from(&self) -> io::Result<(Bytes, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], addr: ServerAddr) -> io::Result<()>;
}

#[async_trait]
pub trait ServerPolicy: Sync + Send {
    fn create_connection_flow_state(&self) -> Option<Arc<FlowStat>>;
    async fn create_out_connection(&self, target_addr: ServerAddr)
        -> io::Result<(TcpStream, Box<dyn ConnectionGuard>)>;
    async fn create_out_udp_socket(&self) -> io::Result<Box<dyn UdpSocket>>;

    async fn stream_check(&self, src_addr: Option<&ServerAddr>, target_addr: &ServerAddr) -> io::Result<StreamAction>;
    async fn packet_check(&self, src_addr: Option<&ServerAddr>, target_addr: &ServerAddr) -> io::Result<PacketAction>;
}
