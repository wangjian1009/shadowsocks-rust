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
#[macro_use(defer)]
extern crate scopeguard;

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

pub mod config;
pub mod context;
pub mod dns_resolver;
pub mod manager;
pub mod net;
pub mod plugin;
pub mod relay;
mod security;
pub mod timeout;
pub mod transport;

#[cfg(feature = "trojan")]
pub mod trojan;

#[cfg(feature = "vless")]
pub mod vless;

#[cfg(test)]
mod test;
