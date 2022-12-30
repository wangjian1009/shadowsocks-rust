//! UDP socket with flow statistic monitored

use std::{io, net::SocketAddr, ops::Deref, sync::Arc};

use async_trait::async_trait;
use shadowsocks::{
    net::FlowStat,
    relay::udprelay::options::UdpSocketControlData,
    transport::{PacketMutWrite, PacketRead, PacketWrite},
    ProxySocket, ServerAddr,
};
use tokio::net::ToSocketAddrs;

/// Monitored `ProxySocket`
pub struct MonProxySocket {
    socket: ProxySocket,
    flow_stat: Arc<FlowStat>,
}

impl MonProxySocket {
    /// Create a new socket with flow monitor
    pub fn from_socket(socket: ProxySocket, flow_stat: Arc<FlowStat>) -> MonProxySocket {
        MonProxySocket { socket, flow_stat }
    }

    /// Send a UDP packet to addr through proxy
    #[inline]
    pub async fn send(&self, addr: &ServerAddr, payload: &[u8]) -> io::Result<()> {
        let n = self.socket.send(addr, payload).await?;
        self.flow_stat.incr_tx(n as u64);

        Ok(())
    }

    /// Send a UDP packet to addr through proxy
    #[inline]
    pub async fn send_with_ctrl(
        &self,
        addr: &ServerAddr,
        control: &UdpSocketControlData,
        payload: &[u8],
    ) -> io::Result<()> {
        let n = self.socket.send_with_ctrl(addr, control, payload).await?;
        self.flow_stat.incr_tx(n as u64);

        Ok(())
    }

    /// Send a UDP packet to target from proxy
    #[inline]
    pub async fn send_to<A: ToSocketAddrs>(&self, target: A, addr: &ServerAddr, payload: &[u8]) -> io::Result<()> {
        let n = self.socket.send_to(target, addr, payload).await?;
        self.flow_stat.incr_tx(n as u64);

        Ok(())
    }

    /// Send a UDP packet to target from proxy
    #[inline]
    pub async fn send_to_with_ctrl<A: ToSocketAddrs>(
        &self,
        target: A,
        addr: &ServerAddr,
        control: &UdpSocketControlData,
        payload: &[u8],
    ) -> io::Result<()> {
        let n = self.socket.send_to_with_ctrl(target, addr, control, payload).await?;
        self.flow_stat.incr_tx(n as u64);

        Ok(())
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    #[inline]
    pub async fn recv(&self, recv_buf: &mut [u8]) -> io::Result<(usize, ServerAddr)> {
        let (n, addr, recv_n) = self.socket.recv(recv_buf).await?;
        self.flow_stat.incr_rx(recv_n as u64);

        Ok((n, addr))
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    #[inline]
    pub async fn recv_with_ctrl(
        &self,
        recv_buf: &mut [u8],
    ) -> io::Result<(usize, ServerAddr, Option<UdpSocketControlData>)> {
        let (n, addr, recv_n, control) = self.socket.recv_with_ctrl(recv_buf).await?;
        self.flow_stat.incr_rx(recv_n as u64);

        Ok((n, addr, control))
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    #[inline]
    pub async fn recv_from(&self, recv_buf: &mut [u8]) -> io::Result<(usize, SocketAddr, ServerAddr)> {
        let (n, peer_addr, addr, recv_n) = self.socket.recv_from(recv_buf).await?;
        self.flow_stat.incr_rx(recv_n as u64);

        Ok((n, peer_addr, addr))
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    #[inline]
    pub async fn recv_from_with_ctrl(
        &self,
        recv_buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, ServerAddr, Option<UdpSocketControlData>)> {
        let (n, peer_addr, addr, recv_n, control) = self.socket.recv_from_with_ctrl(recv_buf).await?;
        self.flow_stat.incr_rx(recv_n as u64);

        Ok((n, peer_addr, addr, control))
    }

    #[inline]
    pub fn get_ref(&self) -> &ProxySocket {
        &self.socket
    }

    #[inline]
    pub fn flow_stat(&self) -> &FlowStat {
        &self.flow_stat
    }
}

pub struct MonProxyWriter {
    bind_addr: Option<SocketAddr>,
    inner: Arc<MonProxySocket>,
}

impl MonProxyWriter {
    pub fn with_peer_addr(bind_addr: SocketAddr, inner: Arc<MonProxySocket>) -> Self {
        Self {
            bind_addr: Some(bind_addr),
            inner,
        }
    }

    pub fn new(inner: Arc<MonProxySocket>) -> Self {
        Self { bind_addr: None, inner }
    }
}

impl Deref for MonProxyWriter {
    type Target = MonProxySocket;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[async_trait]
impl PacketMutWrite for MonProxyWriter {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        match self.bind_addr.as_ref() {
            Some(bind_addr) => {
                self.inner
                    .send_to(bind_addr, &ServerAddr::from(addr.clone()), buf)
                    .await
            }
            None => self.inner.send(&ServerAddr::from(addr.clone()), buf).await,
        }
    }
}

#[async_trait]
impl PacketWrite for MonProxyWriter {
    async fn write_to(&self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        match self.bind_addr.as_ref() {
            Some(bind_addr) => {
                self.inner
                    .send_to(bind_addr, &ServerAddr::from(addr.clone()), buf)
                    .await
            }
            None => self.inner.send(&ServerAddr::from(addr.clone()), buf).await,
        }
    }
}

pub struct MonProxyReader {
    inner: Arc<MonProxySocket>,
}

impl MonProxyReader {
    pub fn new(inner: Arc<MonProxySocket>) -> Self {
        Self { inner }
    }
}

impl Deref for MonProxyReader {
    type Target = MonProxySocket;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[async_trait]
impl PacketRead for MonProxyReader {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (sz, addr) = self.inner.recv(buf).await?;
        Ok((
            sz,
            match addr {
                ServerAddr::SocketAddr(addr) => addr,
                ServerAddr::DomainName(..) => unimplemented!(),
            },
        ))
    }
}
