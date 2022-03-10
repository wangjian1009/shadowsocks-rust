//! Shadowsocks Local Network Utilities

pub use self::{
    tcp::{
        auto_proxy_io::AutoProxyIo,
        auto_proxy_stream::{connect_bypassed, AutoProxyClientStream},
    },
    udp::{UdpAssociationManager, UdpInboundWrite},
};

mod tcp;
mod udp;
