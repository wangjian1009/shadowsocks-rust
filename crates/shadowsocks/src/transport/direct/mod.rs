use std::io;
mod acceptor;
mod connector;
mod packet;

use crate::{net::Destination, ServerAddr};

use super::StreamConnection;
pub use acceptor::TcpAcceptor;
pub use connector::TcpConnector;

impl StreamConnection for crate::net::TcpStream {
    fn local_addr(&self) -> io::Result<Destination> {
        Ok(Destination::Tcp(ServerAddr::SocketAddr(
            crate::net::TcpStream::local_addr(&self)?,
        )))
    }

    fn check_connected(&self) -> bool {
        check_peekable(self)
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, _limiter: Option<std::sync::Arc<crate::transport::RateLimiter>>) {
        log::error!("TcpStream not support set rate-limit")
    }
}

impl StreamConnection for tokio::net::TcpStream {
    fn local_addr(&self) -> io::Result<Destination> {
        Ok(Destination::Tcp(ServerAddr::SocketAddr(
            tokio::net::TcpStream::local_addr(&self)?,
        )))
    }

    fn check_connected(&self) -> bool {
        check_peekable(self)
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, _limiter: Option<std::sync::Arc<crate::transport::RateLimiter>>) {
        log::error!("TcpStream not support set rate-limit")
    }
}

#[cfg(unix)]
impl StreamConnection for tokio::net::UnixStream {
    fn local_addr(&self) -> io::Result<Destination> {
        let addr = tokio::net::UnixStream::local_addr(&self)?;

        match addr.as_pathname() {
            None => Err(io::Error::new(io::ErrorKind::Other, "Unix address is unnamed")),
            Some(path) => match path.to_str() {
                Some(path) => Ok(Destination::Unix(path.to_owned())),
                None => Err(io::Error::new(io::ErrorKind::Other, "Unix address get path fail")),
            },
        }
    }

    fn check_connected(&self) -> bool {
        check_peekable(self)
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, _limiter: Option<std::sync::Arc<crate::transport::RateLimiter>>) {
        log::error!("UnixStream not support set rate-limit")
    }
}

#[cfg(unix)]
fn check_peekable<F: std::os::unix::io::AsRawFd>(fd: &F) -> bool {
    let fd = fd.as_raw_fd();

    unsafe {
        let mut peek_buf = [0u8; 1];

        let ret = libc::recv(
            fd,
            peek_buf.as_mut_ptr() as *mut libc::c_void,
            peek_buf.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        );

        match ret.cmp(&0) {
            // EOF, connection lost
            std::cmp::Ordering::Equal => false,
            // Data in buffer
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => {
                let err = io::Error::last_os_error();
                // EAGAIN, EWOULDBLOCK
                // Still connected.
                err.kind() == io::ErrorKind::WouldBlock
            }
        }
    }
}

#[cfg(windows)]
fn check_peekable<F: std::os::windows::io::AsRawSocket>(s: &F) -> bool {
    use winapi::{
        ctypes::{c_char, c_int},
        um::winsock2::{recv, MSG_PEEK, SOCKET},
    };

    let sock = s.as_raw_socket() as SOCKET;

    unsafe {
        let mut peek_buf = [0u8; 1];

        let ret = recv(
            sock,
            peek_buf.as_mut_ptr() as *mut c_char,
            peek_buf.len() as c_int,
            MSG_PEEK,
        );

        match ret.cmp(&0) {
            // EOF, connection lost
            Ordering::Equal => false,
            // Data in buffer
            Ordering::Greater => true,
            Ordering::Less => {
                let err = io::Error::last_os_error();
                // I have to trust the `s` have already set to non-blocking mode
                // Becuase windows doesn't have MSG_DONTWAIT
                err.kind() == ErrorKind::WouldBlock
            }
        }
    }
}
