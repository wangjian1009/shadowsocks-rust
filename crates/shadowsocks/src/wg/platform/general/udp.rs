use super::super::udp::*;
use super::super::Endpoint;
use async_trait::async_trait;
use cfg_if::cfg_if;

use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

#[cfg(all(unix))]
use std::os::unix::prelude::AsRawFd;

use tokio::{io, net::UdpSocket};

use crate::net::ConnectOpts;

pub struct GeneralUDP();

pub struct GeneralOwner {
    port: u16,
    sock: Arc<UdpSocket>,
}

pub struct GeneralUDPReader {
    sock: Arc<UdpSocket>,
}

#[derive(Clone)]
pub struct GeneralUDPWriter {
    sock: Arc<UdpSocket>,
}

pub struct GeneralEndpoint {
    addr: SocketAddr,
}

impl Endpoint for GeneralEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        GeneralEndpoint { addr }
    }

    fn into_address(&self) -> SocketAddr {
        self.addr
    }

    fn clear_src(&mut self) {}
}

#[async_trait]
impl Reader<GeneralEndpoint> for GeneralUDPReader {
    type Error = io::Error;

    async fn read(&self, buf: &mut [u8]) -> Result<(usize, GeneralEndpoint), Self::Error> {
        tracing::trace!("receive packet, (fd {}, max-len {})", self.sock.as_raw_fd(), buf.len());

        debug_assert!(!buf.is_empty(), "reading into empty buffer (will fail)");

        let (len, addr) = match self.sock.recv_from(buf).await {
            Ok(r) => r,
            Err(err) => {
                tracing::error!(err = ?err, "receive packet error (fd = {})", self.sock.as_raw_fd());
                return Err(err);
            }
        };

        // tracing::error!("xxxxx: {}: <=== IPv6 packet len={}", self.sock.as_raw_fd(), buf.len());
        Ok((len.try_into().unwrap(), GeneralEndpoint { addr }))
    }
}

#[async_trait]
impl Writer<GeneralEndpoint> for GeneralUDPWriter {
    type Error = io::Error;

    async fn write(&self, buf: &[u8], dst: &mut GeneralEndpoint) -> Result<(), Self::Error> {
        tracing::debug!("sending packet ({} fd, {} bytes)", self.sock.as_raw_fd(), buf.len());

        if let Err(err) = self.sock.send_to(buf, dst.addr).await {
            tracing::error!(err = ?err, "failed to send IPv4 packet");
            return Err(err);
        }

        // tracing::error!("xxxxx: {}: ===> packet len={}", self.sock.as_raw_fd(), buf.len());
        Ok(())
    }
}

impl Owner for GeneralOwner {
    type Error = io::Error;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, _value: Option<u32>) -> Result<(), Self::Error> {
        tracing::trace!("ignore set fwmark");
        Ok(())
    }
}

impl Drop for GeneralOwner {
    fn drop(&mut self) {
        tracing::debug!("closing the bind (port = {})", self.port);
        tracing::debug!("shutdown IPv4 (fd = {})", self.sock.as_raw_fd());
        unsafe {
            libc::shutdown(self.sock.as_raw_fd(), libc::SHUT_RDWR);
        }
    }
}

impl UDP for GeneralUDP {
    type Error = std::io::Error;
    type Endpoint = GeneralEndpoint;
    type Writer = GeneralUDPWriter;
    type Reader = GeneralUDPReader;
}

#[async_trait]
impl PlatformUDP for GeneralUDP {
    type Owner = GeneralOwner;

    #[allow(clippy::type_complexity)]
    #[allow(clippy::unnecessary_unwrap)]
    async fn bind(
        mut port: u16,
        _connect_opts: &ConnectOpts,
    ) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        tracing::debug!("bind to port {}", port);

        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        let sock = match UdpSocket::bind(bind_addr).await {
            Ok(sock) => sock,
            Err(err) => {
                tracing::error!(err = ?err, "failed to bind IPv4 socket");
                return Err(err);
            }
        };

        let local_addr = sock.local_addr().unwrap();

        // basic sanity checks
        let new_port = local_addr.port();
        debug_assert_eq!(new_port, if port != 0 { port } else { new_port });
        tracing::trace!("bound IPv4 socket (port {}, fd {})", new_port, sock.as_raw_fd());
        port = new_port;

        // Any traffic to localhost should not be protected
        // This is a workaround for VPNService
        #[cfg(target_os = "android")]
        {
            if let Some(ref path) = _connect_opts.vpn_protect_path {
                vpn_protect(path, sock.as_raw_fd())?;
            }
        }

        let sock = Arc::new(sock);

        // create owner
        let owner = GeneralOwner {
            port,
            sock: sock.clone(),
        };

        // create readers
        let mut readers: Vec<Self::Reader> = Vec::with_capacity(1);
        readers.push(GeneralUDPReader { sock: sock.clone() });
        debug_assert!(!readers.is_empty());

        // create writer
        let writer = GeneralUDPWriter { sock };

        Ok((readers, writer, owner))
    }
}

cfg_if! {
    if #[cfg(target_os = "android")] {
        use std::{
            path::Path,
        };

        use std::os::unix::net::UnixStream;
        use std::os::unix::io::RawFd;
        use std::io::Read;
        use sendfd::SendWithFd;

        /// This is a RPC for Android to `protect()` socket for connecting to remote servers
        ///
        /// https://developer.android.com/reference/android/net/VpnService#protect(java.net.Socket)
        ///
        /// More detail could be found in [shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android) project.
        fn vpn_protect<P: AsRef<Path>>(protect_path: P, fd: RawFd) -> io::Result<()> {
            let mut stream = UnixStream::connect(protect_path)?;

            // send fds
            let dummy: [u8; 1] = [1];
            let fds: [RawFd; 1] = [fd];
            stream.send_with_fd(&dummy, &fds)?;

            // receive the return value
            let mut response = [0; 1];
            stream.read_exact(&mut response)?;

            if response[0] == 0xFF {
                return Err(io::Error::new(io::ErrorKind::Other, "protect() failed"));
            }

            Ok(())
        }
    }
}
