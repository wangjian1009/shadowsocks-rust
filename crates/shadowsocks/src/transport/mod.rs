use async_trait::async_trait;
use cfg_if::cfg_if;
use std::{io, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    net::{ConnectOpts, Destination},
    ServerAddr,
};

mod common;

pub use common::{
    crypt::{Security, SecurityConfig},
    header::{HeaderConfig, HeaderPolicy},
};

mod device;
pub mod direct;
mod dummy_packet;
mod mon_traffic;
mod mut_packet;

pub use device::{Device, DeviceGuard, DeviceOrGuard, PrivateDevice};
pub use dummy_packet::DummyPacket;
pub use mon_traffic::MonTraffic;
pub use mut_packet::MutPacketWriter;

cfg_if! {
    if #[cfg(feature = "rate-limit")] {
        mod rate_limit;

        pub use rate_limit::BoundWidth;
        pub use rate_limit::RateLimiter;
        pub use rate_limit::RateLimitedStream;
    }
}

cfg_if! {
    if #[cfg(feature = "rate-limit")] {
        use std::sync::Arc;
    }
}

#[cfg(feature = "transport-ws")]
pub mod websocket;

#[cfg(feature = "transport-tls")]
pub mod tls;

#[cfg(feature = "transport-mkcp")]
pub mod mkcp;

#[cfg(feature = "transport-skcp")]
pub mod skcp;

/// Stream traits
pub trait StreamConnection: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    fn check_connected(&self) -> bool;

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<Arc<RateLimiter>>);

    fn physical_device(&self) -> DeviceOrGuard<'_>;

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.physical_device().apply(|f| match f {
            Device::Tcp(s) => s.local_addr(),
            Device::Udp(s) => s.local_addr(),
            Device::TofTcp(s) => s.local_addr(),
            Device::Private(s) => s.local_addr(),
        })
    }
}

/// Packet traits
#[async_trait]
pub trait PacketRead: Send + Sync + Unpin {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, ServerAddr)>;
}

#[async_trait]
pub trait PacketMutWrite: Send + Sync + Unpin {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()>;
}

#[async_trait]
pub trait PacketWrite: PacketMutWrite {
    async fn write_to(&self, buf: &[u8], addr: &ServerAddr) -> io::Result<()>;
}

/// Connection;
pub enum Connection<T: StreamConnection, PR: PacketRead, PW: PacketMutWrite> {
    Stream(T),
    Packet { r: PR, w: PW, local_addr: Destination },
}

/// Connector traits
#[async_trait]
pub trait Connector: Send + Sync + Unpin + 'static {
    type TS: StreamConnection + 'static;
    type PR: PacketRead;
    type PW: PacketMutWrite;

    async fn connect(
        &self,
        destination: &Destination,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Connection<Self::TS, Self::PR, Self::PW>>;

    async fn connect_stream(&self, addr: &ServerAddr, connect_opts: &ConnectOpts) -> io::Result<Self::TS> {
        let destination = Destination::Tcp(addr.clone());
        match self.connect(&destination, connect_opts).await? {
            Connection::Stream(stream) => Ok(stream),
            Connection::Packet { .. } => unreachable!(),
        }
    }
}

/// Acceptor
#[async_trait]
pub trait Acceptor: Send + Sync + 'static {
    type TS: StreamConnection + 'static;
    type PR: PacketRead;
    type PW: PacketMutWrite;

    async fn accept(&mut self) -> io::Result<(Connection<Self::TS, Self::PR, Self::PW>, Option<ServerAddr>)>;

    async fn accept_stream(&mut self) -> io::Result<(Self::TS, Option<ServerAddr>)> {
        match self.accept().await? {
            (Connection::Stream(stream), addr) => Ok((stream, addr)),
            (Connection::Packet { .. }, _addr) => unreachable!(),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl StreamConnection for Box<dyn StreamConnection> {
    fn check_connected(&self) -> bool {
        self.as_ref().check_connected()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<Arc<RateLimiter>>) {
        self.as_mut().set_rate_limit(rate_limit)
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        self.as_ref().physical_device()
    }
}
