pub(crate) use super::super::{PacketMutWrite, PacketRead, PacketWrite};
use crate::{net::UdpSocket, ServerAddr};
use async_trait::async_trait;
use std::{io, sync::Arc};

#[async_trait]
impl PacketRead for Arc<UdpSocket> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, ServerAddr)> {
        let (size, addr) = self.recv_from(buf).await?;
        Ok((size, ServerAddr::SocketAddr(addr)))
    }
}

#[async_trait]
impl PacketMutWrite for Arc<UdpSocket> {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        let _ = self.send_to(buf, addr.to_string()).await?;
        Ok(())
    }
}

#[async_trait]
impl PacketWrite for Arc<UdpSocket> {
    async fn write_to(&self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        let _ = self.send_to(buf, addr.to_string()).await?;
        Ok(())
    }
}
