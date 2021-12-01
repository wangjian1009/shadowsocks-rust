use cfg_if::cfg_if;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;

mod password;
pub use password::decrypt_password;

cfg_if! {
    if #[cfg(feature = "host-dns")] {
        pub mod host_dns;
        pub use host_dns::HostDns;
    }
}

#[cfg(feature = "local")]
mod local;
