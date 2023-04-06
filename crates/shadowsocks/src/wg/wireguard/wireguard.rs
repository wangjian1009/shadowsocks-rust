use std::fmt;

use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::time::Instant;

use rand::rngs::OsRng;
use rand::Rng;

// use hjul::Runner;
use tokio::sync::{Mutex, Notify, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::net::ConnectOpts;

use super::constants::*;
use super::handshake;
use super::peer::PeerInner;
use super::router;
use super::timers::Timers;

use super::queue::ParallelQueue;
use super::workers::HandshakeJob;

use super::timer::Runner;
use super::tun::Tun;
use super::udp::UDP;

use super::workers::{handshake_worker, tun_worker, udp_worker};

#[cfg(feature = "rate-limit")]
use crate::transport::RateLimiter;

pub struct WireguardInner<T: Tun, B: UDP> {
    #[cfg(feature = "rate-limit")]
    pub rate_limit: Arc<RateLimiter>,
    pub connect_opts: ConnectOpts,

    // identifier (for logging)
    pub id: u32,

    // timer wheel
    pub runner: Mutex<Runner>,

    // device enabled
    pub enabled: RwLock<bool>,

    // number of tun readers
    pub tun_readers: WaitCounter,

    // current MTU
    pub mtu: AtomicUsize,

    // peer map
    #[allow(clippy::type_complexity)]
    pub peers: RwLock<handshake::Device<router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>>>,

    // cryptokey router
    pub router: router::Device<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>,

    // handshake related state
    pub last_under_load: spin::Mutex<Instant>,
    pub pending: AtomicUsize, // number of pending handshake packets in queue
    pub queue: ParallelQueue<HandshakeJob<B::Endpoint>>,
}

pub struct WireGuard<T: Tun, B: UDP> {
    inner: Arc<WireguardInner<T, B>>,
}

pub struct WaitCounter(Mutex<usize>, Notify);

impl<T: Tun, B: UDP> fmt::Display for WireGuard<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wireguard({:x})", self.id)
    }
}

impl<T: Tun, B: UDP> Deref for WireGuard<T, B> {
    type Target = WireguardInner<T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Tun, B: UDP> Clone for WireGuard<T, B> {
    fn clone(&self) -> Self {
        WireGuard {
            inner: self.inner.clone(),
        }
    }
}

#[allow(clippy::mutex_atomic)]
impl WaitCounter {
    pub async fn wait(&self) {
        while *self.0.lock().await > 0 {
            self.1.notified().await
        }
    }

    fn new() -> Self {
        Self(Mutex::new(0), Notify::new())
    }

    async fn decrease(&self) {
        let need_notify = {
            let mut nread = self.0.lock().await;
            assert!(*nread > 0);
            *nread -= 1;
            *nread == 0
        };

        if need_notify {
            self.1.notify_waiters()
        }
    }

    async fn increase(&self) {
        *self.0.lock().await += 1;
    }
}

impl<T: Tun, B: UDP> WireGuard<T, B> {
    /// Brings the WireGuard device down.
    /// Usually called when the associated interface is brought down.
    ///
    /// This stops any further action/timer on any peer
    /// and prevents transmission of further messages,
    /// however the device retrains its state.
    ///
    /// The instance will continue to consume and discard messages
    /// on both ends of the device.
    pub async fn down(&self) {
        // ensure exclusive access (to avoid race with "up" call)
        let mut enabled = self.enabled.write().await;

        // check if already down
        if !(*enabled) {
            return;
        }

        // set mtu
        self.mtu.store(0, Ordering::Relaxed);

        // avoid transmission from router
        self.router.down();

        // set all peers down (stops timers)
        for (_, peer) in self.peers.write().await.iter() {
            peer.stop_timers().await;
            peer.down();
        }

        *enabled = false;
    }

    /// Brings the WireGuard device up.
    /// Usually called when the associated interface is brought up.
    pub async fn up(&self, mtu: usize) {
        // ensure exclusive access (to avoid race with "up" call)
        let mut enabled = self.enabled.write().await;

        // set mtu
        self.mtu.store(mtu, Ordering::Relaxed);

        // check if already up
        if *enabled {
            return;
        }

        // enable transmission from router
        self.router.up();

        // set all peers up (restarts timers)
        for (_, peer) in self.peers.write().await.iter() {
            peer.up();
            peer.start_timers().await;
        }

        *enabled = true;
    }

    #[cfg(feature = "rate-limit")]
    pub fn rate_limit(&self) -> Arc<RateLimiter> {
        self.inner.rate_limit.clone()
    }

    pub fn connect_opts(&self) -> &ConnectOpts {
        &self.inner.connect_opts
    }

    pub async fn clear_peers(&self) {
        self.peers.write().await.clear();
    }

    pub async fn remove_peer(&self, pk: &PublicKey) {
        let _ = self.peers.write().await.remove(pk);
    }

    pub async fn set_key(&self, sk: Option<StaticSecret>) {
        let mut peers = self.peers.write().await;
        peers.set_sk(sk);
        self.router.clear_sending_keys();
    }

    pub async fn get_sk(&self) -> Option<StaticSecret> {
        self.peers
            .read()
            .await
            .get_sk()
            .map(|sk| StaticSecret::from(sk.to_bytes()))
    }

    pub async fn set_psk(&self, pk: PublicKey, psk: [u8; 32]) -> bool {
        self.peers.write().await.set_psk(pk, psk).is_ok()
    }
    pub async fn get_psk(&self, pk: &PublicKey) -> Option<[u8; 32]> {
        self.peers.read().await.get_psk(pk).ok()
    }

    pub async fn add_peer(&self, pk: PublicKey) -> bool {
        let mut peers = self.peers.write().await;
        if peers.contains_key(&pk) {
            return false;
        }

        // prevent up/down while inserting
        let enabled = self.enabled.read().await;

        // create timers (lookup by public key)
        let timers = Timers::new::<T, B>(self.clone(), pk, *enabled).await;

        // create new router peer
        let peer: router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer> =
            self.router.new_peer(PeerInner {
                id: OsRng.gen(),
                pk,
                wg: self.clone(),
                walltime_last_handshake: spin::Mutex::new(None),
                last_handshake_sent: spin::Mutex::new(Instant::now() - TIME_HORIZON),
                handshake_queued: AtomicBool::new(false),
                rx_bytes: AtomicU64::new(0),
                tx_bytes: AtomicU64::new(0),
                timers: RwLock::new(timers),
            });

        // finally, add the peer to the handshake device
        peers.add(pk, peer).is_ok()
    }

    /// Begin consuming messages from the reader.
    /// Multiple readers can be added to support multi-queue and individual Ipv6/Ipv4 sockets interfaces
    ///
    /// Any previous reader thread is stopped by closing the previous reader,
    /// which unblocks the thread and causes an error on reader.read
    pub fn add_udp_reader(&self, reader: B::Reader) {
        let wg = self.clone();
        tokio::spawn(async move {
            udp_worker(&wg, reader).await;
        });
    }

    pub fn set_writer(&self, writer: B::Writer) {
        self.router.set_outbound_writer(writer);
    }

    pub async fn add_tun_reader(&self, reader: T::Reader) {
        let wg = self.clone();

        // increment reader count
        wg.tun_readers.increase().await;

        // start worker
        tokio::spawn(async move {
            tun_worker(&wg, reader).await;
            wg.tun_readers.decrease().await;
        });
    }

    pub async fn wait(&self) {
        self.tun_readers.wait().await;
    }

    pub fn new(
        writer: T::Writer,
        connect_opts: ConnectOpts,
        #[cfg(feature = "rate-limit")] rate_limit: Arc<RateLimiter>,
    ) -> WireGuard<T, B> {
        // workers equal to number of physical cores
        let cpus = 1; // num_cpus::get();

        // create handshake queue
        let (tx, mut rxs) = ParallelQueue::new(cpus, 128);

        // create router
        let router: router::Device<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer> =
            router::Device::new(cpus, writer);

        // create arc to state
        let wg = WireGuard {
            inner: Arc::new(WireguardInner {
                #[cfg(feature = "rate-limit")]
                rate_limit,
                connect_opts,
                enabled: RwLock::new(false),
                tun_readers: WaitCounter::new(),
                id: OsRng.gen(),
                mtu: AtomicUsize::new(0),
                last_under_load: spin::Mutex::new(Instant::now() - TIME_HORIZON),
                router,
                pending: AtomicUsize::new(0),
                peers: RwLock::new(handshake::Device::new()),
                runner: tokio::sync::Mutex::new(Runner::new(TIMERS_TICK, TIMERS_SLOTS, TIMERS_CAPACITY)),
                queue: tx,
            }),
        };

        // start handshake workers
        while let Some(rx) = rxs.pop() {
            let wg = wg.clone();
            tokio::spawn(async move { handshake_worker(&wg, rx).await });
        }

        wg
    }
}
