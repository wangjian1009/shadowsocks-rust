use async_trait::async_trait;
use cfg_if::cfg_if;
use std::{io, net::SocketAddr, pin::Pin, task};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{net::ConnectOpts, ServerAddr};

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
pub use mon_traffic::{MonTraffic, MonTrafficRead, MonTrafficWrite};
pub use mut_packet::MutPacketWriter;

cfg_if! {
    if #[cfg(feature = "rate-limit")] {
        mod rate_limit;
        pub use rate_limit::{BoundWidth, RateLimiter, RateLimitedStream, NegativeMultiDecision};
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

#[cfg(feature = "transport-restls")]
pub mod restls;

pub trait AsyncPing {
    fn supports_ping(&self) -> bool {
        false
    }

    // Write a ping message to the stream, if supported.
    // This should end up calling the highest level stream abstraction that supports
    // pings, and should only result in a single message.
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> task::Poll<io::Result<bool>> {
        unimplemented!("ping not supported")
    }
}

/// Stream traits
pub trait StreamConnection: AsyncRead + AsyncWrite + AsyncPing + Send + Sync + Unpin {
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
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

#[async_trait]
pub trait PacketMutWrite: Send + Sync + Unpin {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()>;
}

#[async_trait]
pub trait PacketWrite: PacketMutWrite {
    async fn write_to(&self, buf: &[u8], addr: &ServerAddr) -> io::Result<()>;
}

/// Connector traits
#[async_trait]
pub trait Connector: Send + Sync + Unpin + 'static {
    type TS: StreamConnection + 'static;

    async fn connect(&self, addr: &ServerAddr, connect_opts: &ConnectOpts) -> io::Result<Self::TS>;
}

/// Acceptor
#[async_trait]
pub trait Acceptor: Send + Sync + 'static {
    type TS: StreamConnection + 'static;

    async fn accept(&mut self) -> io::Result<(Self::TS, Option<SocketAddr>)>;

    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl AsyncPing for Box<dyn StreamConnection> {
    fn supports_ping(&self) -> bool {
        self.as_ref().supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<bool>> {
        Pin::new(&mut **self).poll_write_ping(cx)
    }
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
