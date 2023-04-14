#[cfg(not(any(target_os = "windows", target_os = "android", target_os = "ios")))]
pub mod device;

mod config;

mod noise;

mod serialization;

pub use config::{Config, IPAddressRange, ItfConfig, PeerConfig};
pub use noise::{
    errors::WireGuardError, handshake::parse_handshake_anon, rate_limiter::RateLimiter, Packet, Tunn, TunnResult,
};
pub use serialization::KeyBytes;
pub use x25519_dalek::{PublicKey, StaticSecret as Secret};
