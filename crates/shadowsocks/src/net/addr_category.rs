use std::{
    convert::From,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::ServerAddr;

pub enum AddrCategory {
    Public,
    Private,
    Loopback,
    Broadcast,
}

impl From<&ServerAddr> for AddrCategory {
    fn from(addr: &ServerAddr) -> Self {
        match addr {
            ServerAddr::SocketAddr(addr) => Self::from(&addr.ip()),
            ServerAddr::DomainName(host, ..) => Self::from_domain(host),
        }
    }
}

impl From<&IpAddr> for AddrCategory {
    fn from(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Self::from(addr),
            IpAddr::V6(addr) => {
                if addr.is_loopback() {
                    AddrCategory::Loopback
                } else if addr.is_multicast() {
                    AddrCategory::Broadcast
                } else {
                    AddrCategory::Public
                }
            }
        }
    }
}

impl From<&Ipv4Addr> for AddrCategory {
    fn from(addr: &Ipv4Addr) -> Self {
        if addr.is_broadcast() {
            AddrCategory::Broadcast
        } else if addr.is_loopback() {
            AddrCategory::Loopback
        } else if addr.is_private() {
            AddrCategory::Private
        } else {
            AddrCategory::Public
        }
    }
}

impl From<&Ipv6Addr> for AddrCategory {
    fn from(addr: &Ipv6Addr) -> Self {
        if let Some(ipv4addr) = addr.to_ipv4_mapped() {
            return Self::from(&ipv4addr);
        }

        if addr.is_loopback() {
            AddrCategory::Loopback
        } else {
            AddrCategory::Public
        }
    }
}

impl AddrCategory {
    pub fn from_domain(domain_name: &str) -> Self {
        if domain_name == "localhost" {
            Self::Loopback
        } else {
            Self::Public
        }
    }
}

impl fmt::Display for AddrCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Broadcast => write!(f, "boradcast"),
            Self::Loopback => write!(f, "loopback"),
            Self::Private => write!(f, "private"),
        }
    }
}
