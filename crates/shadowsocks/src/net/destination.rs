use crate::ServerAddr;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
};

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Destination {
    Tcp(ServerAddr),
    Udp(ServerAddr),
    #[cfg(unix)]
    Unix(String),
}

impl Destination {
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match &self {
            Self::Tcp(addr) => match addr {
                ServerAddr::SocketAddr(addr) => Some(addr.clone()),
                ServerAddr::DomainName(..) => None,
            },
            Self::Udp(addr) => match addr {
                ServerAddr::SocketAddr(addr) => Some(addr.clone()),
                ServerAddr::DomainName(..) => None,
            },
            #[cfg(unix)]
            Self::Unix(..) => None,
        }
    }
}

impl Debug for Destination {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Destination::Tcp(ref addr) => write!(f, "tcp://{}", addr),
            Destination::Udp(ref addr) => write!(f, "udp://{}", addr),
            #[cfg(unix)]
            Destination::Unix(ref addr) => write!(f, "unix://{}", addr),
        }
    }
}

impl fmt::Display for Destination {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Destination::Tcp(ref addr) => write!(f, "tcp{}", addr),
            Destination::Udp(ref addr) => write!(f, "tcp{}", addr),
            #[cfg(unix)]
            Destination::Unix(ref addr) => write!(f, "unix:{}", addr),
        }
    }
}
