use super::timers::Timers;

use super::tun::Tun;
use super::udp::UDP;

use super::constants::REKEY_TIMEOUT;
use super::wireguard::WireGuard;
use super::workers::HandshakeJob;

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::time::Instant;

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use x25519_dalek::PublicKey;

pub struct PeerInner<T: Tun, B: UDP> {
    // internal id (for logging)
    pub id: u64,

    // wireguard device state
    pub wg: WireGuard<T, B>,

    // TODO: eliminate
    pub pk: PublicKey,

    // handshake state
    pub walltime_last_handshake: spin::Mutex<Option<SystemTime>>, /* walltime for last handshake (for UAPI status) */
    pub last_handshake_sent: spin::Mutex<Instant>,                // instant for last handshake
    pub handshake_queued: AtomicBool,                             // is a handshake job currently queued?

    // stats and configuration
    pub rx_bytes: AtomicU64, // received bytes
    pub tx_bytes: AtomicU64, // transmitted bytes

    // timer model
    pub timers: RwLock<Timers>,
}

impl<T: Tun, B: UDP> PeerInner<T, B> {
    /* Queue a handshake request for the parallel workers
     * (if one does not already exist)
     *
     * The function is ratelimited.
     */
    pub async fn packet_send_handshake_initiation(&self) {
        tracing::trace!("{} : packet_send_handshake_initiation", self);

        // the function is rate limited
        {
            let mut lhs = self.last_handshake_sent.lock();
            if lhs.elapsed() < REKEY_TIMEOUT {
                tracing::trace!("{} : packet_send_handshake_initiation, rate-limited!", self);
                return;
            }
            *lhs = Instant::now();
        }

        // create a new handshake job for the peer
        if !self.handshake_queued.swap(true, Ordering::SeqCst) {
            self.wg.pending.fetch_add(1, Ordering::SeqCst);
            self.wg.queue.send(HandshakeJob::New(self.pk)).await;
            tracing::trace!("{} : packet_send_handshake_initiation, handshake queued", self);
        } else {
            tracing::trace!("{} : packet_send_handshake_initiation, handshake already queued", self);
        }
    }

    #[inline(always)]
    pub async fn timers(&self) -> RwLockReadGuard<Timers> {
        self.timers.read().await
    }

    #[inline(always)]
    pub async fn timers_mut(&self) -> RwLockWriteGuard<Timers> {
        self.timers.write().await
    }
}

impl<T: Tun, B: UDP> fmt::Display for PeerInner<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer(id = {})", self.id)
    }
}
