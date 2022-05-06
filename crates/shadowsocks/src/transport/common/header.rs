use std::{fmt, io, str::FromStr};

pub type HeaderPolicy = Box<dyn Header + Send + Sync>;

#[derive(Clone, Debug, PartialEq)]
pub enum HeaderConfig {
    Srtp,
    Utp,
    Dtls,
    Wechat,
    Wireguard,
}

impl HeaderConfig {
    pub fn create_policy(&self) -> HeaderPolicy {
        match self {
            HeaderConfig::Srtp => Box::new(srtp::SRTP::new()) as HeaderPolicy,
            HeaderConfig::Utp => Box::new(utp::UTP::new()) as HeaderPolicy,
            HeaderConfig::Dtls => Box::new(dtls::DTLS::new()) as HeaderPolicy,
            HeaderConfig::Wechat => Box::new(wechat::VideoChat::new()) as HeaderPolicy,
            HeaderConfig::Wireguard => Box::new(wireguard::Wireguard::new()) as HeaderPolicy,
        }
    }
}

impl FromStr for HeaderConfig {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<HeaderConfig, Self::Err> {
        match s {
            "srtp" => Ok(HeaderConfig::Srtp),
            "utp" => Ok(HeaderConfig::Utp),
            "wechat-video" => Ok(HeaderConfig::Wechat),
            "dtls" => Ok(HeaderConfig::Dtls),
            "wireguard" => Ok(HeaderConfig::Wireguard),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("not support header config {}", s),
            )),
        }
    }
}

impl fmt::Display for HeaderConfig {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HeaderConfig::Srtp => write!(f, "srtp"),
            HeaderConfig::Utp => write!(f, "utp"),
            HeaderConfig::Dtls => write!(f, "dtls"),
            HeaderConfig::Wechat => write!(f, "wechat-video"),
            HeaderConfig::Wireguard => write!(f, "wireguard"),
        }
    }
}

pub trait Header {
    fn size(&self) -> usize;
    fn serialize(&self, dst: &mut [u8]);
}

pub mod dtls;
pub mod srtp;
pub mod utp;
pub mod wechat;
pub mod wireguard;
