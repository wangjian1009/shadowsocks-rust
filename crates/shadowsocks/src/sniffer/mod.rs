#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SnifferProtocol {
    Bittorrent,
    Http,
}

#[derive(PartialEq, Debug)]
pub enum SnifferCheckError {
    NoClue,
    Reject,
    Other(String),
}

pub trait Sniffer {
    const PROTOCOL: SnifferProtocol;
    fn check(&mut self, data: &[u8]) -> Result<(), SnifferCheckError>;
}

pub trait SnifferChain {
    fn check(&mut self, data: &[u8]) -> Result<SnifferProtocol, SnifferCheckError>;
}

mod bittorrent;
mod chain;
mod stream;

pub use bittorrent::SnifferBittorrent;
pub use chain::SnifferChainNode;
pub use stream::SnifferStream;
