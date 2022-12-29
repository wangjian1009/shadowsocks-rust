use std::{convert::From, fmt, net::IpAddr};

use crate::ServerAddr;

pub enum AddrType {
    Domainname,
    Ipv4,
    Ipv6,
}

impl From<&ServerAddr> for AddrType {
    fn from(addr: &ServerAddr) -> Self {
        match addr {
            ServerAddr::SocketAddr(addr) => Self::from(&addr.ip()),
            ServerAddr::DomainName(..) => Self::Domainname,
        }
    }
}

impl From<&IpAddr> for AddrType {
    fn from(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(..) => Self::Ipv4,
            IpAddr::V6(..) => Self::Ipv6,
        }
    }
}

impl AddrType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Domainname => "domain",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

impl fmt::Display for AddrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
