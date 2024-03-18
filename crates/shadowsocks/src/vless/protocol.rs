use std::fmt;

use super::{UUID, Address};

#[derive(Clone, Debug, PartialEq)]
pub struct Addons {
    pub flow: Option<String>,
    pub seed: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RequestCommand {
    TCP = 0x01,
    UDP = 0x02,
    Mux = 0x03,
}

impl fmt::Display for RequestCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TCP => write!(f, "tcp"),
            Self::UDP => write!(f, "udp"),
            Self::Mux => write!(f, "mux"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct RequestHeader {
    pub version: u8,
    pub command: RequestCommand,
    pub address: Address,
    pub user: UUID,
}
