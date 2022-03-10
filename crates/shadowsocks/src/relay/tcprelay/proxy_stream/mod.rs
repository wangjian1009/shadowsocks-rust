//! Stream interface for communicating with shadowsocks proxy servers

pub use self::{client::ProxyClientStream, server::ProxyServerStream};

pub mod client;
pub mod server;
