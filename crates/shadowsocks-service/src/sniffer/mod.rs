use cfg_if::cfg_if;

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum SnifferProtocol {
    #[cfg(feature = "sniffer-bittorrent")]
    Bittorrent,
    #[cfg(feature = "sniffer-bittorrent")]
    Utp,
    #[cfg(feature = "sniffer-http")]
    Http,
    #[cfg(feature = "sniffer-tls")]
    Tls(String),
}

#[derive(PartialEq, Debug)]
pub enum SnifferCheckError {
    NoClue,
    Reject,
    Other(String),
}

pub trait Sniffer {
    fn check(&mut self, data: &[u8]) -> Result<SnifferProtocol, SnifferCheckError>;
}

pub trait SnifferChain {
    fn check(&mut self, data: &[u8]) -> Result<SnifferProtocol, SnifferCheckError>;
}

mod chain;
mod stream;

pub use chain::{SnifferChainHead, SnifferChainNode};
pub use stream::SnifferStream;

cfg_if! {
    if #[cfg(feature = "sniffer-bittorrent")] {
        mod bittorrent;
        pub use bittorrent::SnifferBittorrent;

        mod utp;
        pub use utp::SnifferUtp;
    }
}

cfg_if! {
    if #[cfg(feature = "sniffer-tls")] {
        mod tls;
        pub use tls::SnifferTls;
    }
}

fn check_block(data: &[u8], check: &[u8]) -> Result<(), SnifferCheckError> {
    if data.len() < check.len() {
        if data == &check[..data.len()] {
            Err(SnifferCheckError::NoClue)
        } else {
            Err(SnifferCheckError::Reject)
        }
    } else if &data[..check.len()] == check {
        Ok(())
    } else {
        Err(SnifferCheckError::Reject)
    }
}
