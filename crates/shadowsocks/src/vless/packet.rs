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

#[cfg(test)]
mod test {
    use super::{
        super::{protocol::RequestCommand, test_env::connect_external_direct},
        *,
    };
    use tokio_test::assert_ok;

    #[tokio::test]
    #[traced_test]
    async fn test_v2ray_udp_echo() {
        // 通过代理服务连接udp echo 服务 socat
        let echo_svr_addr = "172.104.180.47:50050";
        let stream = assert_ok!(connect_external_direct(RequestCommand::UDP, echo_svr_addr).await);
        let (mut r, mut w) = new_vless_packet_connection(stream);

        assert_ok!(w.write_to_mut(b"1234").await);

        let mut buf: [u8; 1024] = [0u8; 1024];
        let buf_len = assert_ok!(assert_ok!(
            tokio::time::timeout(tokio::time::Duration::from_secs(1), r.read_from(&mut buf)).await
        ));
        assert_eq!(buf_len, 4);

        assert_eq!(b"1234", &buf[..4]);
    }
}
