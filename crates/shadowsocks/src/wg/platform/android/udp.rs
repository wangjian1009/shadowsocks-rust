use super::super::udp::*;
use super::super::Endpoint;
use async_trait::async_trait;

use std::convert::TryInto;
use std::io::{self, Read};
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::{io::RawFd, prelude::AsRawFd};
use std::ptr;
use std::sync::Arc;
use std::{io::ErrorKind, path::Path};

use sendfd::SendWithFd;

use tokio::net::UdpSocket;

use crate::net::ConnectOpts;

#[repr(C, align(1))]
struct ControlHeaderV4 {
    hdr: libc::cmsghdr,
    info: libc::in_pktinfo,
}

#[repr(C, align(1))]
struct ControlHeaderV6 {
    hdr: libc::cmsghdr,
    info: libc::in6_pktinfo,
}

pub struct EndpointV4 {
    dst: libc::sockaddr_in, // destination IP
    info: libc::in_pktinfo, // src & ifindex
}

pub struct EndpointV6 {
    dst: libc::sockaddr_in6, // destination IP
    info: libc::in6_pktinfo, // src & zone id
}

pub struct AndroidUDP();

pub struct AndroidOwner {
    port: u16,
    sock4: Option<Arc<UdpSocket>>,
    sock6: Option<Arc<UdpSocket>>,
}

pub enum AndroidUDPReader {
    V4(Arc<UdpSocket>),
    V6(Arc<UdpSocket>),
}

#[derive(Clone)]
pub struct AndroidUDPWriter {
    sock4: Option<Arc<UdpSocket>>,
    sock6: Option<Arc<UdpSocket>>,
}

pub enum AndroidEndpoint {
    V4(EndpointV4),
    V6(EndpointV6),
}

fn errno() -> libc::c_int {
    unsafe {
        let ptr = libc::__errno();
        if ptr.is_null() {
            0
        } else {
            *ptr
        }
    }
}

fn setsockopt<V: Sized>(fd: RawFd, level: libc::c_int, name: libc::c_int, value: &V) -> Result<(), io::Error> {
    let res = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            mem::transmute(value),
            mem::size_of_val(value).try_into().unwrap(),
        )
    };
    if res == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to set sockopt (res = {}, errno = {})", res, errno()),
        ))
    }
}

#[inline(always)]
fn setsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> Result<(), io::Error> {
    setsockopt(fd, level, name, &value)
}

#[allow(non_snake_case)]
const fn CMSG_ALIGN(len: usize) -> usize {
    ((len) + mem::size_of::<u32>() - 1) & !(mem::size_of::<u32>() - 1)
}

#[allow(non_snake_case)]
const fn CMSG_LEN(len: usize) -> usize {
    CMSG_ALIGN(len + mem::size_of::<libc::cmsghdr>())
}

#[inline(always)]
fn safe_cast<T, D>(v: &mut T) -> *mut D {
    (v as *mut T) as *mut D
}

impl Endpoint for AndroidEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => AndroidEndpoint::V4(EndpointV4 {
                dst: libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: addr.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(*addr.ip()).to_be(),
                    },
                    sin_zero: [0; 8],
                },
                info: libc::in_pktinfo {
                    ipi_ifindex: 0,                            // interface (0 is via routing table)
                    ipi_spec_dst: libc::in_addr { s_addr: 0 }, // src IP (dst of incoming packet)
                    ipi_addr: libc::in_addr { s_addr: 0 },
                },
            }),
            SocketAddr::V6(addr) => AndroidEndpoint::V6(EndpointV6 {
                dst: libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: addr.port().to_be(),
                    sin6_flowinfo: addr.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: addr.ip().octets(),
                    },
                    sin6_scope_id: addr.scope_id(),
                },
                info: libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr { s6_addr: [0; 16] }, // src IP
                    ipi6_ifindex: 0,                                // zone id
                },
            }),
        }
    }

    fn into_address(&self) -> SocketAddr {
        match self {
            AndroidEndpoint::V4(EndpointV4 { ref dst, .. }) => {
                SocketAddr::V4(SocketAddrV4::new(
                    u32::from_be(dst.sin_addr.s_addr).into(), // IPv4 addr
                    u16::from_be(dst.sin_port),               // convert back to native byte-order
                ))
            }
            AndroidEndpoint::V6(EndpointV6 { ref dst, .. }) => SocketAddr::V6(SocketAddrV6::new(
                u128::from_ne_bytes(dst.sin6_addr.s6_addr).into(), // IPv6 addr
                u16::from_be(dst.sin6_port),                       // convert back to native byte-order
                dst.sin6_flowinfo,
                dst.sin6_scope_id,
            )),
        }
    }

    fn clear_src(&mut self) {
        match self {
            AndroidEndpoint::V4(EndpointV4 { ref mut info, .. }) => {
                info.ipi_ifindex = 0;
                info.ipi_spec_dst = libc::in_addr { s_addr: 0 };
            }
            AndroidEndpoint::V6(EndpointV6 { ref mut info, .. }) => {
                info.ipi6_addr = libc::in6_addr { s6_addr: [0; 16] };
                info.ipi6_ifindex = 0;
            }
        };
    }
}

impl AndroidUDPReader {
    async fn read6(sock: &UdpSocket, buf: &mut [u8]) -> Result<(usize, AndroidEndpoint), io::Error> {
        tracing::trace!("receive IPv6 packet, (fd {}, max-len {})", sock.as_raw_fd(), buf.len());

        debug_assert!(!buf.is_empty(), "reading into empty buffer (will fail)");

        loop {
            tracing::error!("xxxxx: {}: wait read6 begin", sock.as_raw_fd());
            if let Err(err) = sock.readable().await {
                tracing::error!(err = ?err, "wait readable IPv6 packet fail");
                return Err(err);
            }
            tracing::error!("xxxxx: {}: wait read6 end", sock.as_raw_fd());

            let mut iovs: [libc::iovec; 1] = [libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut core::ffi::c_void,
                iov_len: buf.len(),
            }];
            let mut src: libc::sockaddr_in6 = unsafe { mem::MaybeUninit::zeroed().assume_init() };
            let mut control: ControlHeaderV6 = unsafe { mem::MaybeUninit::zeroed().assume_init() };
            let mut hdr = libc::msghdr {
                msg_name: safe_cast(&mut src),
                msg_namelen: mem::size_of_val(&src) as libc::socklen_t,
                msg_iov: iovs.as_mut_ptr(),
                msg_iovlen: iovs.len(),
                msg_control: safe_cast(&mut control),
                msg_controllen: mem::size_of_val(&control),
                msg_flags: 0,
            };

            debug_assert!(hdr.msg_controllen >= mem::size_of::<libc::cmsghdr>() + mem::size_of::<libc::in6_pktinfo>(),);

            let len = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut hdr as *mut libc::msghdr, 0) };

            if len <= 0 {
                let sys_err = errno();
                if sys_err == libc::EAGAIN || sys_err == libc::EWOULDBLOCK {
                    tracing::debug!("read IPv6 packet wouldblock");
                    continue;
                }

                // TODO: FIX!
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!(
                        "failed to receive (len = {}, fd = {}, errno = {})",
                        len,
                        sock.as_raw_fd(),
                        sys_err,
                    ),
                ));
            }

            tracing::error!("xxxxxx: {}: <== receiving IPv6 packet {} bytes", sock.as_raw_fd(), len);

            return Ok((
                len.try_into().unwrap(),
                AndroidEndpoint::V6(EndpointV6 {
                    info: control.info, // save pktinfo (sticky source)
                    dst: src,           // our future destination is the source address
                }),
            ));
        }
    }

    async fn read4(sock: &UdpSocket, buf: &mut [u8]) -> Result<(usize, AndroidEndpoint), io::Error> {
        tracing::trace!("receive IPv4 packet, (fd {}, max-len {})", sock.as_raw_fd(), buf.len());

        debug_assert!(!buf.is_empty(), "reading into empty buffer (will fail)");

        loop {
            tracing::error!("xxxxx: {}: wait read begin", sock.as_raw_fd());
            if let Err(err) = sock.readable().await {
                tracing::error!(err = ?err, "wait readable IPv4 packet fail");
                return Err(err);
            }
            tracing::error!("xxxxx: {}: wait read end", sock.as_raw_fd());

            let mut iovs: [libc::iovec; 1] = [libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut core::ffi::c_void,
                iov_len: buf.len(),
            }];
            let mut src: libc::sockaddr_in = unsafe { mem::MaybeUninit::zeroed().assume_init() };
            let mut control: ControlHeaderV4 = unsafe { mem::MaybeUninit::zeroed().assume_init() };
            let mut hdr = libc::msghdr {
                msg_name: safe_cast(&mut src),
                msg_namelen: mem::size_of_val(&src) as libc::socklen_t,
                msg_iov: iovs.as_mut_ptr(),
                msg_iovlen: iovs.len(),
                msg_control: safe_cast(&mut control),
                msg_controllen: mem::size_of_val(&control),
                msg_flags: 0,
            };

            debug_assert!(hdr.msg_controllen >= mem::size_of::<libc::cmsghdr>() + mem::size_of::<libc::in_pktinfo>(),);

            let len = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut hdr as *mut libc::msghdr, 0) };

            if len <= 0 {
                let sys_err = errno();
                if sys_err == libc::EAGAIN || sys_err == libc::EWOULDBLOCK {
                    tracing::debug!("read IPv4 packet wouldblock");
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!(
                        "failed to receive (len = {}, fd = {}, errno = {})",
                        len,
                        sock.as_raw_fd(),
                        sys_err
                    ),
                ));
            }

            tracing::error!("xxxxxx: {}: <== receiving IPv4 packet {} bytes", sock.as_raw_fd(), len);

            return Ok((
                len.try_into().unwrap(),
                AndroidEndpoint::V4(EndpointV4 {
                    info: control.info, // save pktinfo (sticky source)
                    dst: src,           // our future destination is the source address
                }),
            ));
        }
    }
}

#[async_trait]
impl Reader<AndroidEndpoint> for AndroidUDPReader {
    type Error = io::Error;

    async fn read(&self, buf: &mut [u8]) -> Result<(usize, AndroidEndpoint), Self::Error> {
        match self {
            Self::V4(sock) => Self::read4(sock, buf).await,
            Self::V6(sock) => Self::read6(sock, buf).await,
        }
    }
}

impl AndroidUDPWriter {
    async fn write6(sock: &UdpSocket, buf: &[u8], dst: &mut EndpointV6) -> Result<(), io::Error> {
        tracing::debug!("sending IPv6 packet ({} fd, {} bytes)", sock.as_raw_fd(), buf.len());

        let mut cleared = true;
        loop {
            if let Err(err) = sock.writable().await {
                tracing::error!(err = ?err, "wait writable IPv6 packet fail");
                return Err(err);
            }

            let mut iovs: [libc::iovec; 1] = [libc::iovec {
                iov_base: buf.as_ptr() as *mut core::ffi::c_void,
                iov_len: buf.len(),
            }];

            let mut control = ControlHeaderV6 {
                hdr: libc::cmsghdr {
                    cmsg_len: CMSG_LEN(mem::size_of::<libc::in6_pktinfo>()),
                    cmsg_level: libc::IPPROTO_IPV6,
                    cmsg_type: libc::IPV6_PKTINFO,
                },
                info: dst.info,
            };

            debug_assert_eq!(
                control.hdr.cmsg_len % mem::size_of::<u32>(),
                0,
                "cmsg_len must be aligned to a long"
            );

            debug_assert_eq!(
                dst.dst.sin6_family,
                libc::AF_INET6 as libc::sa_family_t,
                "this method only handles IPv6 destinations"
            );

            let mut hdr = libc::msghdr {
                msg_name: safe_cast(&mut dst.dst),
                msg_namelen: mem::size_of_val(&dst.dst) as libc::socklen_t,
                msg_iov: iovs.as_mut_ptr(),
                msg_iovlen: iovs.len(),
                msg_control: safe_cast(&mut control),
                msg_controllen: mem::size_of_val(&control),
                msg_flags: 0,
            };

            let ret = unsafe { libc::sendmsg(sock.as_raw_fd(), &hdr, 0) };

            if ret < 0 {
                let sys_err = errno();
                if sys_err == libc::EAGAIN || sys_err == libc::EWOULDBLOCK {
                    tracing::debug!("write IPv6 packet wouldblock");
                    continue;
                } else if sys_err == libc::EINVAL && !cleared {
                    cleared = true;
                    tracing::trace!("clear source and retry");
                    hdr.msg_control = ptr::null_mut();
                    hdr.msg_controllen = 0;
                    dst.info = unsafe { mem::zeroed() };
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "failed to send IPv6 packet",
                ));
            }

            tracing::error!(
                "xxxxxx: {}: => sending IPv6 packet {} bytes",
                sock.as_raw_fd(),
                buf.len()
            );
            return Ok(());
        }
    }

    async fn write4(sock: &UdpSocket, buf: &[u8], dst: &mut EndpointV4) -> Result<(), io::Error> {
        tracing::debug!("sending IPv4 packet ({} fd, {} bytes)", sock.as_raw_fd(), buf.len());

        let mut cleared = false;
        loop {
            if let Err(err) = sock.writable().await {
                tracing::error!(err = ?err, "wait writable IPv4 packet fail");
                return Err(err);
            }

            let mut iovs: [libc::iovec; 1] = [libc::iovec {
                iov_base: buf.as_ptr() as *mut core::ffi::c_void,
                iov_len: buf.len(),
            }];

            let mut control = ControlHeaderV4 {
                hdr: libc::cmsghdr {
                    cmsg_len: CMSG_LEN(mem::size_of::<libc::in_pktinfo>()),
                    cmsg_level: libc::IPPROTO_IP,
                    cmsg_type: libc::IP_PKTINFO,
                },
                info: dst.info,
            };

            debug_assert_eq!(
                control.hdr.cmsg_len % mem::size_of::<u32>(),
                0,
                "cmsg_len must be aligned to a long"
            );

            debug_assert_eq!(
                dst.dst.sin_family,
                libc::AF_INET as libc::sa_family_t,
                "this method only handles IPv4 destinations"
            );

            let mut hdr = libc::msghdr {
                msg_name: safe_cast(&mut dst.dst),
                msg_namelen: mem::size_of_val(&dst.dst) as libc::socklen_t,
                msg_iov: iovs.as_mut_ptr(),
                msg_iovlen: iovs.len(),
                msg_control: safe_cast(&mut control),
                msg_controllen: mem::size_of_val(&control),
                msg_flags: 0,
            };

            let ret = unsafe { libc::sendmsg(sock.as_raw_fd(), &hdr, 0) };

            if ret < 0 {
                let sys_err = errno();
                if sys_err == libc::EAGAIN || sys_err == libc::EWOULDBLOCK {
                    tracing::debug!("write IPv4 packet wouldblock");
                    continue;
                } else if sys_err == libc::EINVAL && !cleared {
                    cleared = true;

                    tracing::trace!("clear source and retry");
                    hdr.msg_control = ptr::null_mut();
                    hdr.msg_controllen = 0;
                    dst.info = unsafe { mem::zeroed() };
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "failed to send IPv4 packet",
                ));
            }

            tracing::error!(
                "xxxxxx: {}: => sending IPv4 packet {} bytes",
                sock.as_raw_fd(),
                buf.len()
            );
            return Ok(());
        }
    }
}

#[async_trait]
impl Writer<AndroidEndpoint> for AndroidUDPWriter {
    type Error = io::Error;

    async fn write(&self, buf: &[u8], dst: &mut AndroidEndpoint) -> Result<(), Self::Error> {
        match dst {
            AndroidEndpoint::V4(ref mut end) => match self.sock4.as_ref() {
                Some(sock) => Self::write4(sock, buf, end).await,
                None => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "failed to send IPv4 packet(no socket)",
                )),
            },
            AndroidEndpoint::V6(ref mut end) => match self.sock6.as_ref() {
                Some(sock) => Self::write6(sock, buf, end).await,
                None => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "failed to send IPv6 packet(no socket)",
                )),
            },
        }
    }
}

impl Owner for AndroidOwner {
    type Error = io::Error;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), Self::Error> {
        fn set_mark(fd: Option<RawFd>, value: u32) -> Result<(), io::Error> {
            if let Some(fd) = fd {
                setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, &value)
            } else {
                Ok(())
            }
        }
        let value = value.unwrap_or(0);
        set_mark(self.sock6.as_ref().map(|sock| sock.as_raw_fd()), value)?;
        set_mark(self.sock4.as_ref().map(|sock| sock.as_raw_fd()), value)
    }
}

impl Drop for AndroidOwner {
    fn drop(&mut self) {
        tracing::debug!("closing the bind (port = {})", self.port);
        if let Some(sock) = &self.sock4 {
            tracing::debug!("shutdown IPv4 (fd = {})", sock.as_raw_fd());
            unsafe {
                libc::shutdown(sock.as_raw_fd(), libc::SHUT_RDWR);
            }
        };
        if let Some(sock) = &self.sock6 {
            tracing::debug!("shutdown IPv6 (fd = {})", sock.as_raw_fd());
            unsafe {
                libc::shutdown(sock.as_raw_fd(), libc::SHUT_RDWR);
            }
        };
    }
}

impl UDP for AndroidUDP {
    type Error = io::Error;
    type Endpoint = AndroidEndpoint;
    type Writer = AndroidUDPWriter;
    type Reader = AndroidUDPReader;
}

impl AndroidUDP {
    /* Bind on all IPv6 interfaces
     *
     * Arguments:
     *
     * - 'port', port to bind to (0 = any)
     *
     * Returns:
     *
     * Returns a tuple of the resulting port and socket.
     */
    fn bind6(port: u16) -> Result<(u16, RawFd), io::Error> {
        tracing::trace!("attempting to bind on IPv6 (port {})", port);

        // create socket fd
        let fd: RawFd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            tracing::debug!("failed to create IPv6 socket (errno = {})", errno());
            return Err(io::Error::new(io::ErrorKind::Other, "failed to create socket"));
        }

        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;

        const INADDR_ANY: libc::in6_addr = libc::in6_addr { s6_addr: [0; 16] };

        // bind
        let mut sockaddr = libc::sockaddr_in6 {
            sin6_addr: INADDR_ANY,
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: port.to_be(), // convert to network (big-endian) byte-order
            sin6_scope_id: 0,
            sin6_flowinfo: 0,
        };

        let err = unsafe {
            libc::bind(
                fd,
                safe_cast(&mut sockaddr),
                mem::size_of_val(&sockaddr).try_into().unwrap(),
            )
        };
        if err != 0 {
            tracing::debug!("failed to bind IPv6 socket (errno = {})", errno());
            return Err(io::Error::new(io::ErrorKind::Other, "failed to create socket"));
        }

        // get the assigned port
        let mut socklen: libc::socklen_t = mem::size_of_val(&sockaddr).try_into().unwrap();
        let err = unsafe { libc::getsockname(fd, safe_cast(&mut sockaddr), &mut socklen as *mut libc::socklen_t) };
        if err != 0 {
            tracing::debug!("failed to get port of IPv6 socket (errno  = {})", errno());
            return Err(io::Error::new(io::ErrorKind::Other, "failed to create socket"));
        }

        // basic sanity checks
        let new_port = u16::from_be(sockaddr.sin6_port);
        debug_assert_eq!(socklen, mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t);
        debug_assert_eq!(sockaddr.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        debug_assert_eq!(new_port, if port != 0 { port } else { new_port });
        tracing::trace!("bound IPv6 socket (port {}, fd {})", new_port, fd);
        Ok((new_port, fd))
    }

    /* Bind on all IPv4 interfaces.
     *
     * Arguments:
     *
     * - 'port', port to bind to (0 = any)
     *
     * Returns:
     *
     * Returns a tuple of the resulting port and socket.
     */
    fn bind4(port: u16) -> Result<(u16, RawFd), io::Error> {
        tracing::trace!("attempting to bind on IPv4 (port {})", port);

        // create socket fd
        let fd: RawFd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            tracing::debug!("failed to create IPv4 socket (errno = {})", errno());
            return Err(io::Error::new(io::ErrorKind::Other, "failed to create socket"));
        }

        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;

        const INADDR_ANY: libc::in_addr = libc::in_addr { s_addr: 0 };

        // bind
        let mut sockaddr = libc::sockaddr_in {
            sin_addr: INADDR_ANY,
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_zero: [0; 8],
        };

        let err = unsafe {
            libc::bind(
                fd,
                safe_cast(&mut sockaddr),
                mem::size_of_val(&sockaddr).try_into().unwrap(),
            )
        };
        if err != 0 {
            tracing::debug!("failed to bind IPv4 socket (errno = {})", errno());
            return Err(io::Error::new(io::ErrorKind::Other, "failed to create socket"));
        }

        // get the assigned port
        let mut socklen: libc::socklen_t = mem::size_of_val(&sockaddr).try_into().unwrap();
        let err = unsafe { libc::getsockname(fd, safe_cast(&mut sockaddr), &mut socklen as *mut libc::socklen_t) };
        if err != 0 {
            tracing::debug!("failed to get port of IPv4 socket (errno = {})", errno());
            return Err(io::Error::new(io::ErrorKind::Other, "failed to create socket"));
        }

        // basic sanity checks
        let new_port = u16::from_be(sockaddr.sin_port);
        debug_assert_eq!(socklen, mem::size_of::<libc::sockaddr_in>() as libc::socklen_t);
        debug_assert_eq!(sockaddr.sin_family, libc::AF_INET as libc::sa_family_t);
        debug_assert_eq!(new_port, if port != 0 { port } else { new_port });
        tracing::trace!("bound IPv4 socket (port {}, fd {})", new_port, fd);
        Ok((new_port, fd))
    }

    fn to_socket(fd: RawFd) -> io::Result<UdpSocket> {
        let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        std_sock.set_nonblocking(true)?;
        UdpSocket::from_std(std_sock)
    }
}

#[async_trait]
impl PlatformUDP for AndroidUDP {
    type Owner = AndroidOwner;

    #[allow(clippy::type_complexity)]
    #[allow(clippy::unnecessary_unwrap)]
    async fn bind(
        mut port: u16,
        connect_opts: &ConnectOpts,
    ) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        tracing::debug!("bind to port {}", port);

        // attempt to bind on ipv6
        let bind6 = Self::bind6(port);
        if let Ok((new_port, _)) = bind6 {
            port = new_port;
        }

        // attempt to bind on ipv4 on the same port
        let bind4 = Self::bind4(port);
        if let Ok((new_port, _)) = bind4 {
            port = new_port;
        }

        // check if failed to bind on both
        if bind4.is_err() && bind6.is_err() {
            tracing::trace!("failed to bind for either IP version");
            return Err(bind6.unwrap_err());
        }

        // Any traffic to localhost should not be protected
        // This is a workaround for VPNService
        if let Some(ref path) = connect_opts.vpn_protect_path {
            // RPC calls to `VpnService.protect()`
            // Timeout in 3 seconds like shadowsocks-libev
            if let Ok((_, fd)) = bind4 {
                vpn_protect(path, fd)?;
            }

            if let Ok((_, fd)) = bind6 {
                vpn_protect(path, fd)?;
            }
        }

        let sock6 = bind6.ok().map(|(_, fd)| Arc::new(Self::to_socket(fd).unwrap()));
        let sock4 = bind4.ok().map(|(_, fd)| Arc::new(Self::to_socket(fd).unwrap()));

        // create owner
        let owner = AndroidOwner {
            port,
            sock6: sock6.clone(),
            sock4: sock4.clone(),
        };

        // create readers
        let mut readers: Vec<Self::Reader> = Vec::with_capacity(2);
        if let Some(sock) = sock6.clone() {
            readers.push(AndroidUDPReader::V6(sock))
        }
        if let Some(sock) = sock4.clone() {
            readers.push(AndroidUDPReader::V4(sock))
        }
        debug_assert!(!readers.is_empty());

        // create writer
        let writer = AndroidUDPWriter { sock4, sock6 };

        Ok((readers, writer, owner))
    }
}

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
        return Err(io::Error::new(ErrorKind::Other, "protect() failed"));
    }

    Ok(())
}
