use cfg_if::cfg_if;

mod endpoint;

pub mod tun;
pub mod uapi;
pub mod udp;

pub use endpoint::Endpoint;

#[cfg(test)]
pub mod dummy;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub mod linux;
        pub use linux as plt;
    }
}

cfg_if! {
    if #[cfg(target_os = "android")] {
        pub mod android;
        pub use android as plt;
    }
}

cfg_if! {
    if #[cfg(any(target_os = "macos", target_os = "ios", target_os = "watchos", target_os = "tvos"))] {
        pub mod apple;
        pub use apple as plt;
    }
}

cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "macos", target_os = "ios"))] {
        pub mod general;
    }
}
