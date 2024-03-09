//! Shadowsocks Core Library

#![crate_type = "lib"]
// #![feature(trait_alias)]
// #![feature(map_try_insert)]
// #![feature(assert_matches)]
// #![feature(linked_list_cursors)]

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(test)]
#[macro_use]
extern crate tracing_test;

// #[cfg(test)]
// #[macro_use(defer)]
// extern crate scopeguard;

#[cfg(test)]
#[macro_use]
extern crate mockall;

pub use self::{
    config::{ManagerAddr, ServerAddr, ServerConfig},
    manager::{ManagerClient, ManagerListener},
    relay::{
        tcprelay::{ProxyClientStream, ProxyListener},
        udprelay::proxy_socket::ProxySocket,
    },
};

pub use shadowsocks_crypto as crypto;

pub mod canceler;
pub mod config;
pub mod context;
pub mod dns_resolver;
pub mod manager;
pub mod net;
pub mod plugin;
pub mod policy;
pub mod relay;
mod security;
pub mod timeout;
pub mod transport;
mod read_line;
pub mod util;

#[cfg(any(feature = "tuic", feature = "transport-tls"))]
pub mod ssl;

#[cfg(feature = "trojan")]
pub mod trojan;

#[cfg(feature = "vless")]
pub mod vless;

#[cfg(feature = "tuic")]
pub mod tuic;

#[cfg(feature = "wireguard")]
pub mod wg;

#[cfg(test)]
mod test;

#[cfg(feature = "statistics")]
#[macro_use]
extern crate metrics;

#[cfg(feature = "statistics")]
pub mod statistics;
