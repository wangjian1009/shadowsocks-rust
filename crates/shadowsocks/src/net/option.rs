//! Options for connecting to remote server

use std::{net::IpAddr, time::Duration};

/// Options for connecting to TCP remote server
#[derive(Debug, Clone, Default)]
pub struct TcpSocketOpts {
    /// TCP socket's `SO_SNDBUF`
    pub send_buffer_size: Option<u32>,

    /// TCP socket's `SO_RCVBUF`
    pub recv_buffer_size: Option<u32>,

    /// `TCP_NODELAY`
    pub nodelay: bool,

    /// `TCP_FASTOPEN`, enables TFO
    pub fastopen: bool,

    /// `SO_KEEPALIVE` and sets `TCP_KEEPIDLE`, `TCP_KEEPINTVL` and `TCP_KEEPCNT` respectively,
    /// enables keep-alive messages on connection-oriented sockets
    pub keepalive: Option<Duration>,

    /// Enable Multipath-TCP (mptcp)
    /// https://en.wikipedia.org/wiki/Multipath_TCP
    ///
    /// Currently only supported on
    /// - macOS (iOS, watchOS, ...) with Client Support only.
    /// - Linux (>5.19)
    pub mptcp: bool,
}

/// Options for UDP server
#[derive(Debug, Clone, Default)]
pub struct UdpSocketOpts {
    /// Maximum Transmission Unit (MTU) for UDP socket `recv`
    ///
    /// NOTE: MTU includes IP header, UDP header, UDP payload
    pub mtu: Option<usize>,
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "android")] {
        /// Protect file descriptor with VPNService
        pub trait VpnFdProtector {
            fn protect_fd(&self, fd: std::os::unix::io::RawFd) -> std::io::Result<()>;
        }

        #[derive(Clone)]
        pub struct VpnFdProtectorCallback {
            processor: std::sync::Arc<Box<dyn VpnFdProtector + Sync + Send>>,
        }

        impl VpnFdProtectorCallback {
            pub fn protect_fd(&self, fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
                (**self.processor).protect_fd(fd)
            }

            pub fn new(processor: impl VpnFdProtector + Sync + Send + 'static) -> VpnFdProtectorCallback {
                VpnFdProtectorCallback {
                    processor: std::sync::Arc::new(Box::new(processor) as Box<dyn VpnFdProtector + Sync + Send>),
                }
            }
        }

        impl std::fmt::Debug for VpnFdProtectorCallback {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("VpnFdProtectorCallback").finish()
            }
        }

        #[derive(Clone, Debug)]
        pub enum VpnProtectPath {
            Path(std::path::PathBuf),
            Callback(VpnFdProtectorCallback),
        }
    }
}

/// Options for connecting to remote server
#[derive(Debug, Clone, Default)]
pub struct ConnectOpts {
    /// Linux mark based routing, going to set by `setsockopt` with `SO_MARK` option
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fwmark: Option<u32>,

    /// FreeBSD SO_USER_COOKIE
    /// https://www.freebsd.org/cgi/man.cgi?query=setsockopt&sektion=2
    #[cfg(target_os = "freebsd")]
    pub user_cookie: Option<u32>,

    /// An IPC unix socket path for sending file descriptors to call `VpnService.protect`
    ///
    /// This is an [Android shadowsocks implementation](https://github.com/shadowsocks/shadowsocks-android) specific feature
    #[cfg(target_os = "android")]
    pub vpn_protect_path: Option<VpnProtectPath>,

    /// Outbound socket binds to this IP address, mostly for choosing network interfaces
    ///
    /// It only affects sockets that trying to connect to addresses with the same family
    pub bind_local_addr: Option<IpAddr>,

    /// Outbound socket binds to interface
    pub bind_interface: Option<String>,

    /// TCP options
    pub tcp: TcpSocketOpts,

    /// UDP options
    pub udp: UdpSocketOpts,

    /// disable_ip_fragmentation
    pub disable_ip_fragmentation: Option<bool>,
}

/// Inbound connection options
#[derive(Clone, Debug, Default)]
pub struct AcceptOpts {
    /// TCP options
    pub tcp: TcpSocketOpts,

    /// UDP options
    pub udp: UdpSocketOpts,

    /// Enable IPV6_V6ONLY option for socket
    pub ipv6_only: bool,
}
