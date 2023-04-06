use async_trait::async_trait;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use x25519_dalek::{PublicKey, StaticSecret};

use tokio::sync::{Mutex, MutexGuard};

use super::udp::Owner;
use super::*;

/// The goal of the configuration interface is, among others,
/// to hide the IO implementations (over which the WG device is generic),
/// from the configuration and UAPI code.
///
/// Furthermore it forms the simpler interface for embedding WireGuard in other applications,
/// and hides the complex types of the implementation from the host application.

/// Describes a snapshot of the state of a peer
pub struct PeerState {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_time: Option<(u64, u64)>,
    pub public_key: PublicKey,
    pub allowed_ips: Vec<(IpAddr, u32)>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: u64,
    pub preshared_key: [u8; 32], // 0^32 is the "default value" (though treated like any other psk)
}

pub struct WireGuardConfig<T: tun::Tun, B: udp::PlatformUDP>(Arc<Mutex<Inner<T, B>>>);

struct Inner<T: tun::Tun, B: udp::PlatformUDP> {
    wireguard: WireGuard<T, B>,
    port: u16,
    bind: Option<B::Owner>,
    fwmark: Option<u32>,
}

impl<T: tun::Tun, B: udp::PlatformUDP> WireGuardConfig<T, B> {
    async fn lock(&self) -> MutexGuard<Inner<T, B>> {
        self.0.lock().await
    }
}

impl<T: tun::Tun, B: udp::PlatformUDP> WireGuardConfig<T, B> {
    pub fn new(wg: WireGuard<T, B>) -> WireGuardConfig<T, B> {
        WireGuardConfig(Arc::new(Mutex::new(Inner {
            wireguard: wg,
            port: 0,
            bind: None,
            fwmark: None,
        })))
    }
}

impl<T: tun::Tun, B: udp::PlatformUDP> Clone for WireGuardConfig<T, B> {
    fn clone(&self) -> Self {
        WireGuardConfig(self.0.clone())
    }
}

/// Exposed configuration interface
#[async_trait]
pub trait Configuration {
    async fn up(&self, mtu: usize) -> Result<(), ConfigError>;

    async fn down(&self);

    /// Updates the private key of the device
    ///
    /// # Arguments
    ///
    /// - `sk`: The new private key (or None, if the private key should be cleared)
    async fn set_private_key(&self, sk: Option<StaticSecret>);

    /// Returns the private key of the device
    ///
    /// # Returns
    ///
    /// The private if set, otherwise None.
    async fn get_private_key(&self) -> Option<StaticSecret>;

    /// Returns the protocol version of the device
    ///
    /// # Returns
    ///
    /// An integer indicating the protocol version
    async fn get_protocol_version(&self) -> usize;

    async fn set_listen_port(&self, port: u16) -> Result<(), ConfigError>;

    /// Set the firewall mark (or similar, depending on platform)
    ///
    /// # Arguments
    ///
    /// - `mark`: The fwmark value
    ///
    /// # Returns
    ///
    /// An error if this operation is not supported by the underlying
    /// "bind" implementation.
    async fn set_fwmark(&self, mark: Option<u32>) -> Result<(), ConfigError>;

    /// Removes all peers from the device
    async fn replace_peers(&self);

    /// Remove the peer from the
    ///
    /// # Arguments
    ///
    /// - `peer`: The public key of the peer to remove
    ///
    /// # Returns
    ///
    /// If the peer does not exists this operation is a noop
    async fn remove_peer(&self, peer: &PublicKey);

    /// Adds a new peer to the device
    ///
    /// # Arguments
    ///
    /// - `peer`: The public key of the peer to add
    ///
    /// # Returns
    ///
    /// A bool indicating if the peer was added.
    ///
    /// If the peer already exists this operation is a noop
    async fn add_peer(&self, peer: &PublicKey) -> bool;

    /// Update the psk of a peer
    ///
    /// # Arguments
    ///
    /// - `peer`: The public key of the peer
    /// - `psk`: The new psk or None if the psk should be unset
    ///
    /// # Returns
    ///
    /// An error if no such peer exists
    async fn set_preshared_key(&self, peer: &PublicKey, psk: [u8; 32]);

    /// Update the endpoint of the
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    /// - `psk`
    async fn set_endpoint(&self, peer: &PublicKey, addr: SocketAddr);

    /// Update the endpoint of the
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    /// - `psk`
    async fn set_persistent_keepalive_interval(&self, peer: &PublicKey, secs: u64);

    /// Remove all allowed IPs from the peer
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    ///
    /// # Returns
    ///
    /// An error if no such peer exists
    async fn replace_allowed_ips(&self, peer: &PublicKey);

    /// Add a new allowed subnet to the peer
    ///
    /// # Arguments
    ///
    /// - `peer`: The public key of the peer
    /// - `ip`: Subnet mask
    /// - `masklen`:
    ///
    /// # Returns
    ///
    /// An error if the peer does not exist
    async fn add_allowed_ip(&self, peer: &PublicKey, ip: IpAddr, masklen: u32);

    async fn get_listen_port(&self) -> Option<u16>;

    /// Returns the state of all peers
    ///
    /// # Returns
    ///
    /// A list of structures describing the state of each peer
    async fn get_peers(&self) -> Vec<PeerState>;

    async fn get_fwmark(&self) -> Option<u32>;
}

async fn start_listener<T: tun::Tun, B: udp::PlatformUDP>(cfg: &mut Inner<T, B>) -> Result<(), ConfigError> {
    cfg.bind = None;

    // create new listener
    let (mut readers, writer, mut owner) = match B::bind(cfg.port, cfg.wireguard.connect_opts()).await {
        Ok(r) => r,
        Err(_) => {
            return Err(ConfigError::FailedToBind);
        }
    };

    // set fwmark
    let _ = owner.set_fwmark(cfg.fwmark); // TODO: handle

    // set writer on WireGuard
    cfg.wireguard.set_writer(writer);

    // add readers
    while let Some(reader) = readers.pop() {
        cfg.wireguard.add_udp_reader(reader);
    }

    // create new UDP state
    cfg.bind = Some(owner);
    Ok(())
}

#[async_trait]
impl<T: tun::Tun, B: udp::PlatformUDP> Configuration for WireGuardConfig<T, B> {
    async fn up(&self, mtu: usize) -> Result<(), ConfigError> {
        tracing::info!("configuration, set device up");
        let mut cfg = self.lock().await;
        cfg.wireguard.up(mtu).await;
        start_listener(&mut *cfg).await
    }

    async fn down(&self) {
        tracing::info!("configuration, set device down");
        let mut cfg = self.lock().await;
        cfg.wireguard.down().await;
        cfg.bind = None;
    }

    async fn get_fwmark(&self) -> Option<u32> {
        self.lock().await.fwmark
    }

    async fn set_private_key(&self, sk: Option<StaticSecret>) {
        tracing::info!("configuration, set private key");
        self.lock().await.wireguard.set_key(sk).await
    }

    async fn get_private_key(&self) -> Option<StaticSecret> {
        self.lock().await.wireguard.get_sk().await
    }

    async fn get_protocol_version(&self) -> usize {
        1
    }

    async fn get_listen_port(&self) -> Option<u16> {
        let st = self.lock().await;
        tracing::trace!("Config, Get listen port, bound: {}", st.bind.is_some());
        st.bind.as_ref().map(|bind| bind.get_port())
    }

    async fn set_listen_port(&self, port: u16) -> Result<(), ConfigError> {
        tracing::trace!("Config, Set listen port: {:?}", port);

        // update port and take old bind
        let mut cfg = self.lock().await;
        let bound: bool = {
            let old = mem::replace(&mut cfg.bind, None);
            cfg.port = port;
            old.is_some()
        };

        // restart listener if bound
        if bound {
            start_listener(&mut *cfg).await
        } else {
            Ok(())
        }
    }

    async fn set_fwmark(&self, mark: Option<u32>) -> Result<(), ConfigError> {
        tracing::trace!("Config, Set fwmark: {:?}", mark);
        match self.lock().await.bind.as_mut() {
            Some(bind) => {
                if bind.set_fwmark(mark).is_err() {
                    Err(ConfigError::IOError)
                } else {
                    Ok(())
                }
            }
            None => Ok(()),
        }
    }

    async fn replace_peers(&self) {
        self.lock().await.wireguard.clear_peers().await;
    }

    async fn remove_peer(&self, peer: &PublicKey) {
        self.lock().await.wireguard.remove_peer(peer).await;
    }

    async fn add_peer(&self, peer: &PublicKey) -> bool {
        self.lock().await.wireguard.add_peer(*peer).await
    }

    async fn set_preshared_key(&self, peer: &PublicKey, psk: [u8; 32]) {
        self.lock().await.wireguard.set_psk(*peer, psk).await;
    }

    async fn set_endpoint(&self, peer: &PublicKey, addr: SocketAddr) {
        if let Some(peer) = self.lock().await.wireguard.peers.read().await.get(peer) {
            peer.set_endpoint(B::Endpoint::from_address(addr));
        }
    }

    async fn set_persistent_keepalive_interval(&self, peer: &PublicKey, secs: u64) {
        if let Some(peer) = self.lock().await.wireguard.peers.read().await.get(peer) {
            peer.opaque().set_persistent_keepalive_interval(secs).await;
        }
    }

    async fn replace_allowed_ips(&self, peer: &PublicKey) {
        if let Some(peer) = self.lock().await.wireguard.peers.read().await.get(peer) {
            peer.remove_allowed_ips();
        }
    }

    async fn add_allowed_ip(&self, peer: &PublicKey, ip: IpAddr, masklen: u32) {
        if let Some(peer) = self.lock().await.wireguard.peers.read().await.get(peer) {
            peer.add_allowed_ip(ip, masklen);
        }
    }

    /*


    pub fn list_peers(
        &self,
    ) -> Vec<(
        PublicKey,
        router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>,
    )> {
        let peers = self.peers.read();
        let mut list = Vec::with_capacity(peers.len());
        for (k, v) in peers.iter() {
            debug_assert!(k.as_bytes() == v.opaque().pk.as_bytes());
            list.push((k.clone(), v.clone()));
        }
        list
    }
    */

    async fn get_peers(&self) -> Vec<PeerState> {
        let cfg = self.lock().await;
        let peers = cfg.wireguard.peers.read().await;
        let mut state = Vec::with_capacity(peers.len());

        for (pk, p) in peers.iter() {
            // convert the system time to (secs, nano) since epoch
            let last_handshake_time = (*p.walltime_last_handshake.lock()).map(|t| {
                let duration = t
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0));
                (duration.as_secs(), duration.subsec_nanos() as u64)
            });

            if let Some(psk) = cfg.wireguard.get_psk(&pk).await {
                // extract state into PeerState
                state.push(PeerState {
                    preshared_key: psk,
                    endpoint: p.get_endpoint(),
                    rx_bytes: p.rx_bytes.load(Ordering::Relaxed),
                    tx_bytes: p.tx_bytes.load(Ordering::Relaxed),
                    persistent_keepalive_interval: p.get_keepalive_interval().await,
                    allowed_ips: p.list_allowed_ips(),
                    last_handshake_time,
                    public_key: pk,
                })
            }
        }
        state
    }
}
