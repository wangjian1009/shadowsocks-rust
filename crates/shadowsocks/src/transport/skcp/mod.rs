//! Library of KCP on Tokio

pub use self::{
    config::{KcpConfig as SkcpConfig, KcpNoDelayConfig},
    connector::SkcpConnector,
    listener::KcpListener as SkcpAcceptor,
    stream::KcpStream as SkcpStream,
};

fn new_error<T: ToString>(message: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("skcp: {}", message.to_string()))
}

mod config;
mod connector;
mod io;
mod kcp;
mod listener;
mod session;
mod skcp;
mod stream;
mod utils;
