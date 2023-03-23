#![cfg_attr(feature = "unstable", feature(test))]

extern crate alloc;

mod config;
mod configuration;
mod platform;
mod wireguard;

pub use config::{Config, IPAddressRange, ItfConfig, PeerConfig, WG_KEY_LEN};
pub use configuration::{set_configuration, Configuration, WireGuardConfig};
pub use platform::plt;
pub use wireguard::WireGuard;
