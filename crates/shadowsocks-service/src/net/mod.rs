//! Shadowsocks Service Network Utilities

pub use self::{
    mon_socket::{MonProxyReader, MonProxySocket, MonProxyWriter},
    mon_stream::MonProxyStream,
};

// pub mod flow;
#[cfg(target_os = "macos")]
pub mod launch_activate_socket;
pub mod mon_socket;
pub mod mon_stream;
pub mod packet_window;
pub mod utils;

/// Packet size for all UDP associations' send queue
pub const UDP_ASSOCIATION_SEND_CHANNEL_SIZE: usize = 1024;

/// Keep-alive channel size for UDP associations' manager
pub const UDP_ASSOCIATION_CLOSE_CHANNEL_SIZE: usize = 64;
