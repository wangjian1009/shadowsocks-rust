use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::new_error;

pub struct VlessUdpReader<T> {
    inner: ReadHalf<T>,
}

impl<T: AsyncRead + Unpin + Send + Sync> VlessUdpReader<T> {
    pub async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.inner.read_u16().await? as usize;
        if len > buf.len() {
            return Err(new_error(format!(
                "packet len {} overflow, buf.len = {}",
                len,
                buf.len()
            )));
        }

        self.inner.read_exact(&mut buf[..len]).await?;
        Ok(len)
    }
}

pub struct VlessUdpWriter<T> {
    inner: WriteHalf<T>,
}

impl<T: AsyncWrite + Unpin + Send + Sync> VlessUdpWriter<T> {
    pub async fn write_to_mut(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_u16(buf.len() as u16).await?;
        self.inner.write_all(buf).await?;
        Ok(())
    }
}

pub fn new_vless_packet_connection<S>(inner: S) -> (VlessUdpReader<S>, VlessUdpWriter<S>)
where
    S: AsyncRead + AsyncWrite,
{
    let (r, w) = tokio::io::split(inner);
    let reader = VlessUdpReader { inner: r };
    let writer = VlessUdpWriter { inner: w };
    (reader, writer)
}
