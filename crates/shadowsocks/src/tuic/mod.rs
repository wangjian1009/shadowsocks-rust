use std::{fmt, io, str::FromStr};

pub mod client;
mod protocol;
pub mod server;

#[derive(Clone, Debug, PartialEq)]
pub enum CongestionController {
    Cubic,
    NewReno,
    Bbr,
}

impl fmt::Display for CongestionController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cubic => write!(f, "cubic"),
            Self::NewReno => write!(f, "new_reno"),
            Self::Bbr => write!(f, "bbr"),
        }
    }
}

impl FromStr for CongestionController {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("cubic") {
            Ok(Self::Cubic)
        } else if s.eq_ignore_ascii_case("new_reno") || s.eq_ignore_ascii_case("newreno") {
            Ok(Self::NewReno)
        } else if s.eq_ignore_ascii_case("bbr") {
            Ok(Self::Bbr)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("not support CongestionController {}", s),
            ))
        }
    }
}
