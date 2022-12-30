use std::io;

use crate::{relay::socks5::Address, ServerAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

pub struct TrojanUdpReader<T> {
    inner: ReadHalf<T>,
}

use super::protocol;

impl<T: AsyncRead + Unpin + Send + Sync> TrojanUdpReader<T> {
    pub async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, ServerAddr)> {
        let header = protocol::UdpHeader::read_from(&mut self.inner).await?;
        self.inner.read_exact(&mut buf[..header.payload_len as usize]).await?;
        Ok((header.payload_len as usize, header.address.into()))
    }
}

pub struct TrojanUdpWriter<T> {
    inner: WriteHalf<T>,
}

impl<T: AsyncWrite + Unpin + Send + Sync> TrojanUdpWriter<T> {
    pub async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        let header = protocol::UdpHeader::new(
            match addr {
                ServerAddr::SocketAddr(addr) => Address::SocketAddress(addr.clone()),
                ServerAddr::DomainName(path, port) => Address::DomainNameAddress(path.clone(), port.clone()),
            },
            buf.len(),
        );
        header.write_to(&mut self.inner).await?;
        let _ = self.inner.write(buf).await?;
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
