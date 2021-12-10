use cfg_if::cfg_if;

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum SnifferProtocol {
    #[cfg(feature = "sniffer-bittorrent")]
    Bittorrent,
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
    }
}

cfg_if! {
    if #[cfg(feature = "sniffer-tls")] {
        mod tls;
        pub use tls::SnifferTls;
    }
}
