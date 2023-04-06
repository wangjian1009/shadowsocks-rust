use super::Endpoint;
use async_trait::async_trait;
use std::error::Error;

use crate::net::ConnectOpts;

#[async_trait]
pub trait Reader<E: Endpoint>: Send + Sync {
    type Error: Error;

    async fn read(&self, buf: &mut [u8]) -> Result<(usize, E), Self::Error>;
}

#[async_trait]
pub trait Writer<E: Endpoint>: Send + Sync + 'static {
    type Error: Error;

    async fn write(&self, buf: &[u8], dst: &mut E) -> Result<(), Self::Error>;
}

pub trait UDP: Send + Sync + 'static {
    type Error: Error;
    type Endpoint: Endpoint;

    /* Until Rust gets type equality constraints these have to be generic */
    type Writer: Writer<Self::Endpoint>;
    type Reader: Reader<Self::Endpoint>;
}

/// On platforms where fwmark can be set and the
/// implementation can bind to a new port during later configuration (UAPI support),
/// this type provides the ability to set the fwmark and close the socket (by dropping the instance)
pub trait Owner: Send {
    type Error: Error;

    fn get_port(&self) -> u16;

    fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), Self::Error>;
}

/// On some platforms the application can itself bind to a socket.
/// This enables configuration using the UAPI interface.
#[async_trait]
pub trait PlatformUDP: UDP {
    type Owner: Owner;

    /// Bind to a new port, returning the reader/writer and
    /// an associated instance of the owner type, which closes the UDP socket upon "drop"
    /// and enables configuration of the fwmark value.
    #[allow(clippy::type_complexity)]
    async fn bind(
        port: u16,
        connect_opts: &ConnectOpts,
    ) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error>;
}
