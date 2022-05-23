mod acceptor;
mod connector;
mod packet;

use super::{Device, DeviceOrGuard, StreamConnection};
pub use acceptor::TcpAcceptor;
use cfg_if::cfg_if;
pub use connector::TcpConnector;

impl StreamConnection for crate::net::TcpStream {
    fn check_connected(&self) -> bool {
        crate::net::check_peekable(self)
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, _limiter: Option<std::sync::Arc<crate::transport::RateLimiter>>) {
        log::error!("TcpStream not support set rate-limit")
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        cfg_if! {
            if #[cfg(any(target_os = "macos", target_os = "ios", target_os = "watchos", target_os = "tvos", target_os = "freebsd"))] {
                match self.inner() {
                    crate::net::sys::TcpStream::Standard(s) => DeviceOrGuard::Device(Device::Tcp(s)),
                    crate::net::sys::TcpStream::FastOpen(s) => DeviceOrGuard::Device(Device::TofTcp(s)),
                }
            }
            else {
                DeviceOrGuard::Device(Device::Tcp(self.inner()))
            }
        }
    }
}

impl StreamConnection for tokio::net::TcpStream {
    fn check_connected(&self) -> bool {
        crate::net::check_peekable(self)
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, _limiter: Option<std::sync::Arc<crate::transport::RateLimiter>>) {
        log::error!("TcpStream not support set rate-limit")
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        DeviceOrGuard::Device(Device::Tcp(self))
    }
}
