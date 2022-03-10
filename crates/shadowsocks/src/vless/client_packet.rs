use std::{io, sync::Arc};

use crate::{
    transport::{PacketMutWrite, PacketRead},
    ServerAddr,
};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::new_error;

pub struct VlessUdpReader<T> {
    target_addr: Arc<ServerAddr>,
    inner: ReadHalf<T>,
}

#[async_trait]
impl<T: AsyncRead + Unpin + Send + Sync> PacketRead for VlessUdpReader<T> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, ServerAddr)> {
        let len = self.inner.read_u16().await? as usize;
        if len > buf.len() {
            return Err(new_error(format!(
                "packet len {} overflow, buf.len = {}",
                len,
                buf.len()
            )));
        }

        self.inner.read_exact(&mut buf[..len]).await?;
        Ok((len, self.target_addr.as_ref().clone()))
    }
}

pub struct VlessUdpWriter<T> {
    target_addr: Arc<ServerAddr>,
    inner: WriteHalf<T>,
}

#[async_trait]
impl<T: AsyncWrite + Unpin + Send + Sync> PacketMutWrite for VlessUdpWriter<T> {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        if addr != self.target_addr.as_ref() {
            // panic!("target addr mismatch, expect {} but {}", self.target_addr, &addr);
            return Err(new_error(format!(
                "target addr mismatch, expect {} but {}",
                self.target_addr, &addr
            )));
        }

        self.inner.write_u16(buf.len() as u16).await?;

        self.inner.write_all(buf).await?;

        Ok(())
    }
}

pub fn new_vless_packet_connection<S>(inner: S, target_addr: ServerAddr) -> (VlessUdpReader<S>, VlessUdpWriter<S>)
where
    S: AsyncRead + AsyncWrite,
{
    let target_addr = Arc::new(target_addr);
    let (r, w) = tokio::io::split(inner);
    let reader = VlessUdpReader {
        inner: r,
        target_addr: target_addr.clone(),
    };
    let writer = VlessUdpWriter { inner: w, target_addr };
    (reader, writer)
}
