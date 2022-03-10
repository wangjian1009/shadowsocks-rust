use std::{fmt, io, str::FromStr};

use super::new_error;

#[derive(Clone, Debug, PartialEq)]
pub enum HeaderConfig {
    Srtp,
    Utp,
    Dtls,
    Wechat,
    Wireguard,
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
            _ => Err(new_error(format!("not support header config {}", s))),
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
