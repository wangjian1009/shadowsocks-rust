use std::io;

use crate::{
    relay::socks5::Address,
    transport::{PacketMutWrite, PacketRead},
    ServerAddr,
};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

pub struct TrojanUdpReader<T> {
    inner: ReadHalf<T>,
}

use super::protocol;

#[async_trait]
impl<T: AsyncRead + Unpin + Send + Sync> PacketRead for TrojanUdpReader<T> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, ServerAddr)> {
        let header = protocol::UdpHeader::read_from(&mut self.inner).await?;
        self.inner.read_exact(&mut buf[..header.payload_len as usize]).await?;
        Ok((header.payload_len as usize, header.address.into()))
    }
}

pub struct TrojanUdpWriter<T> {
    inner: WriteHalf<T>,
}

#[async_trait]
impl<T: AsyncWrite + Unpin + Send + Sync> PacketMutWrite for TrojanUdpWriter<T> {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        let header = protocol::UdpHeader::new(
            match addr {
                ServerAddr::SocketAddr(addr) => Address::SocketAddress(addr.clone()),
                ServerAddr::DomainName(path, port) => Address::DomainNameAddress(path.clone(), port.clone()),
            },
            buf.len(),
        );
        header.write_to(&mut self.inner).await?;
        self.inner.write(buf).await?;
        Ok(())
    }
}

pub fn new_trojan_packet_connection<S>(inner: S) -> (TrojanUdpReader<S>, TrojanUdpWriter<S>)
where
    S: AsyncRead + AsyncWrite,
{
    let (r, w) = tokio::io::split(inner);
    let reader = TrojanUdpReader { inner: r };
    let writer = TrojanUdpWriter { inner: w };
    (reader, writer)
}
