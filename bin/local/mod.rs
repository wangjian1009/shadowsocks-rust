#[cfg(feature = "host-dns")]
pub mod host_dns;

#[cfg(feature = "host-dns")]
pub use host_dns::HostDns;

mod password;
pub use password::decrypt_password;
