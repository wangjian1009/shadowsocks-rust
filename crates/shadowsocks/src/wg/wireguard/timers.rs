use async_trait::async_trait;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::time::{Duration, Instant};

use tracing::debug;

// use hjul::Timer;
use x25519_dalek::PublicKey;

use super::constants::*;
use super::peer::PeerInner;
use super::router::{message_data_len, Callbacks};
use super::timer::Timer;
use super::tun::Tun;
use super::types::KeyPair;
use super::udp::UDP;
use super::WireGuard;

pub struct Timers {
    // only updated during configuration
    enabled: bool,
    keepalive_interval: u64,

    handshake_attempts: AtomicUsize,
    sent_lastminute_handshake: AtomicBool,
    need_another_keepalive: AtomicBool,

    retransmit_handshake: Timer,
    send_keepalive: Timer,
    send_persistent_keepalive: Timer,
    zero_key_material: Timer,
    new_handshake: Timer,
}

impl Timers {
    #[inline(always)]
    fn need_another_keepalive(&self) -> bool {
        self.need_another_keepalive.swap(false, Ordering::SeqCst)
    }
}

impl<T: Tun, B: UDP> PeerInner<T, B> {
    pub async fn get_keepalive_interval(&self) -> u64 {
        self.timers().await.keepalive_interval
    }

    pub async fn stop_timers(&self) {
        // take a write lock preventing simultaneous timer events or "start_timers" call
        let mut timers = self.timers_mut().await;

        // set flag to prevent future timer events
        if !timers.enabled {
            return;
        }
        timers.enabled = false;

        // stop all pending timers
        timers.retransmit_handshake.stop();
        timers.send_keepalive.stop();
        timers.send_persistent_keepalive.stop();
        timers.zero_key_material.stop();
        timers.new_handshake.stop();

        // reset all timer state
        timers.handshake_attempts.store(0, Ordering::SeqCst);
        timers.sent_lastminute_handshake.store(false, Ordering::SeqCst);
        timers.need_another_keepalive.store(false, Ordering::SeqCst);
    }

    pub async fn start_timers(&self) {
        // take a write lock preventing simultaneous "stop_timers" call
        let mut timers = self.timers_mut().await;

        // set flag to reenable timer events
        if timers.enabled {
            return;
        }
        timers.enabled = true;

        // start send_persistent_keepalive
        if timers.keepalive_interval > 0 {
            timers.send_persistent_keepalive.start(Duration::from_secs(0));
        }
    }

    /* should be called after an authenticated data packet is sent */
    pub async fn timers_data_sent(&self) {
        let timers = self.timers().await;
        if timers.enabled {
            timers.new_handshake.start(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        }
    }

    /* should be called after an authenticated data packet is received */
    pub async fn timers_data_received(&self) {
        let timers = self.timers().await;
        if timers.enabled && !timers.send_keepalive.start(KEEPALIVE_TIMEOUT) {
            timers.need_another_keepalive.store(true, Ordering::SeqCst)
        }
    }

    /* Should be called after any type of authenticated packet is sent, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub async fn timers_any_authenticated_packet_sent(&self) {
        tracing::trace!("timers_any_authenticated_packet_sent");
        let timers = self.timers().await;
        if timers.enabled {
            timers.send_keepalive.stop()
        }
    }

    /* Should be called after any type of authenticated packet is received, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub async fn timers_any_authenticated_packet_received(&self) {
        tracing::trace!("timers_any_authenticated_packet_received");
        let timers = self.timers().await;
        if timers.enabled {
            timers.new_handshake.stop();
        }
    }

    /* Should be called after a handshake initiation message is sent. */
    pub async fn timers_handshake_initiated(&self) {
        tracing::trace!("timers_handshake_initiated");
        let timers = self.timers().await;
        if timers.enabled {
            timers.send_keepalive.stop();
            timers.retransmit_handshake.reset(REKEY_TIMEOUT);
        }
    }

    /* Should be called after a handshake response message is received and processed
     * or when getting key confirmation via the first data message.
     */
    pub async fn timers_handshake_complete(&self) {
        tracing::trace!("timers_handshake_complete");
        let timers = self.timers().await;
        if timers.enabled {
            timers.retransmit_handshake.stop();
            timers.handshake_attempts.store(0, Ordering::SeqCst);
            timers.sent_lastminute_handshake.store(false, Ordering::SeqCst);
            *self.walltime_last_handshake.lock() = Some(SystemTime::now());
        }
    }

    /* Should be called after an ephemeral key is created, which is before sending a
     * handshake response or after receiving a handshake response.
     */
    pub async fn timers_session_derived(&self) {
        tracing::trace!("timers_session_derived");
        let timers = self.timers().await;
        if timers.enabled {
            timers.zero_key_material.reset(REJECT_AFTER_TIME * 3);
        }
    }

    /* Should be called before a packet with authentication, whether
     * keepalive, data, or handshake is sent, or after one is received.
     */
    pub async fn timers_any_authenticated_packet_traversal(&self) {
        tracing::trace!("timers_any_authenticated_packet_traversal");
        let timers = self.timers().await;
        if timers.enabled && timers.keepalive_interval > 0 {
            // push persistent_keepalive into the future
            timers
                .send_persistent_keepalive
                .reset(Duration::from_secs(timers.keepalive_interval));
        }
    }

    async fn timers_set_retransmit_handshake(&self) {
        tracing::trace!("timers_set_retransmit_handshake");
        let timers = self.timers().await;
        if timers.enabled {
            timers.retransmit_handshake.reset(REKEY_TIMEOUT);
        }
    }

    /* Called after a handshake worker sends a handshake initiation to the peer
     */
    pub async fn sent_handshake_initiation(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.timers_handshake_initiated().await;
        self.timers_set_retransmit_handshake().await;
        self.timers_any_authenticated_packet_traversal().await;
        self.timers_any_authenticated_packet_sent().await;
    }

    pub async fn sent_handshake_response(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.timers_any_authenticated_packet_traversal().await;
        self.timers_any_authenticated_packet_sent().await;
    }

    pub async fn set_persistent_keepalive_interval(&self, secs: u64) {
        let mut timers = self.timers_mut().await;

        // update the stored keepalive_interval
        timers.keepalive_interval = secs;

        // stop the keepalive timer with the old interval
        timers.send_persistent_keepalive.stop();

        // cause immediate expiry of persistent_keepalive timer
        if secs > 0 && timers.enabled {
            timers.send_persistent_keepalive.reset(Duration::from_secs(0));
        }
    }

    async fn packet_send_queued_handshake_initiation(&self, is_retry: bool) {
        if !is_retry {
            self.timers().await.handshake_attempts.store(0, Ordering::SeqCst);
        }
        self.packet_send_handshake_initiation().await;
    }
}

impl Timers {
    pub async fn new<T: Tun, B: UDP>(
        wg: WireGuard<T, B>, // WireGuard device
        pk: PublicKey,       // public key of peer
        running: bool,       // timers started
    ) -> Timers {
        macro_rules! fetch_peer {
            ( $wg:expr, $pk:expr, $peer:ident) => {
                let peers = $wg.peers.read().await;
                let $peer = match peers.get(&$pk) {
                    None => {
                        return;
                    }
                    Some(peer) => peer,
                };
            };
        }

        macro_rules! fetch_timers {
            ( $peer:ident, $timers:ident) => {
                let $timers = $peer.timers().await;
                if !$timers.enabled {
                    return;
                }
            };
        }

        let runner = wg.runner.lock().await;

        // create a timer instance for the provided peer
        Timers {
            enabled: running,
            keepalive_interval: 0, // disabled
            need_another_keepalive: AtomicBool::new(false),
            sent_lastminute_handshake: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: {
                let wg = wg.clone();
                runner.timer(move || {
                    let wg = wg.clone();
                    async move {
                        // fetch peer by public key
                        fetch_peer!(wg, pk, peer);
                        fetch_timers!(peer, timers);

                        // check if handshake attempts remaining
                        let attempts = timers.handshake_attempts.fetch_add(1, Ordering::SeqCst);
                        if attempts > MAX_TIMER_HANDSHAKES {
                            debug!(
                                "Handshake for peer {} did not complete after {} attempts, giving up",
                                peer,
                                attempts + 1
                            );
                            timers.send_keepalive.stop();
                            timers.zero_key_material.start(REJECT_AFTER_TIME * 3);
                            peer.purge_staged_packets();
                        } else {
                            debug!(
                                "Handshake for {} did not complete after {} seconds, retrying (try {})",
                                peer,
                                REKEY_TIMEOUT.as_secs(),
                                attempts
                            );
                            timers.retransmit_handshake.reset(REKEY_TIMEOUT);
                            peer.clear_src();
                            peer.packet_send_queued_handshake_initiation(true).await;
                        }
                    }
                })
            },
            send_keepalive: {
                let wg = wg.clone();
                runner.timer(move || {
                    let wg = wg.clone();
                    async move {
                        // fetch peer by public key
                        fetch_peer!(wg, pk, peer);
                        fetch_timers!(peer, timers);

                        // send keepalive and schedule next keepalive
                        peer.send_keepalive().await;
                        if timers.need_another_keepalive() {
                            timers.send_keepalive.start(KEEPALIVE_TIMEOUT);
                        }
                    }
                })
            },
            new_handshake: {
                let wg = wg.clone();
                runner.timer(move || {
                    let wg = wg.clone();
                    async move {
                        // fetch peer by public key
                        fetch_peer!(wg, pk, peer);
                        fetch_timers!(peer, timers);

                        // clear source and retry
                        tracing::debug!(
                            "Retrying handshake with {} because we stopped hearing back after {} seconds",
                            peer,
                            (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT).as_secs()
                        );
                        peer.clear_src();
                        peer.packet_send_queued_handshake_initiation(false).await;
                    }
                })
            },
            zero_key_material: {
                let wg = wg.clone();
                runner.timer(move || {
                    let wg = wg.clone();
                    async move {
                        // fetch peer by public key
                        fetch_peer!(wg, pk, peer);
                        tracing::trace!("{} : timer fired (zero_key_material)", peer);

                        // null all key-material
                        peer.zero_keys();
                    }
                })
            },
            send_persistent_keepalive: {
                let wg = wg.clone();
                runner.timer(move || {
                    let wg = wg.clone();
                    async move {
                        // fetch peer by public key
                        fetch_peer!(wg, pk, peer);
                        fetch_timers!(peer, timers);
                        tracing::trace!("{} : timer fired (send_persistent_keepalive)", peer);

                        // send and schedule persistent keepalive
                        if timers.keepalive_interval > 0 {
                            timers.send_keepalive.stop();
                            peer.send_keepalive().await;
                            tracing::trace!("{} : keepalive queued", peer);
                            timers
                                .send_persistent_keepalive
                                .start(Duration::from_secs(timers.keepalive_interval));
                        }
                    }
                })
            },
        }
    }
}

#[async_trait]
impl<T: Tun, B: UDP> Callbacks for PeerInner<T, B> {
    type Opaque = Self;

    /* Called after the router encrypts a transport message destined for the peer.
     * This method is called, even if the encrypted payload is empty (keepalive)
     */
    #[inline(always)]
    async fn send(peer: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64) {
        tracing::trace!("{} : EVENT(send)", peer);

        // update timers and stats

        peer.timers_any_authenticated_packet_traversal().await;
        peer.timers_any_authenticated_packet_sent().await;
        peer.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);
        if size > message_data_len(0) && sent {
            peer.timers_data_sent().await;
        }

        // keep_key_fresh

        fn keep_key_fresh(keypair: &Arc<KeyPair>, counter: u64) -> bool {
            counter > REKEY_AFTER_MESSAGES || (keypair.initiator && Instant::now() - keypair.birth > REKEY_AFTER_TIME)
        }

        if keep_key_fresh(keypair, counter) {
            peer.packet_send_queued_handshake_initiation(false).await;
        }
    }

    /* Called after the router successfully decrypts a transport message from a peer.
     * This method is called, even if the decrypted packet is:
     *
     * - A keepalive
     * - A malformed IP packet
     * - Fails to cryptkey route
     */
    #[inline(always)]
    async fn recv(peer: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>) {
        tracing::trace!("{} : EVENT(recv)", peer);

        // update timers and stats

        peer.timers_any_authenticated_packet_traversal().await;
        peer.timers_any_authenticated_packet_received().await;
        peer.rx_bytes.fetch_add(size as u64, Ordering::Relaxed);
        if size > 0 && sent {
            peer.timers_data_received().await;
        }

        // keep_key_fresh

        #[inline(always)]
        fn keep_key_fresh(keypair: &Arc<KeyPair>) -> bool {
            Instant::now() - keypair.birth > REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
        }

        if keep_key_fresh(keypair)
            && !peer
                .timers()
                .await
                .sent_lastminute_handshake
                .swap(true, Ordering::Acquire)
        {
            peer.packet_send_queued_handshake_initiation(false).await;
        }
    }

    /* Called every time the router detects that a key is required,
     * but no valid key-material is available for the particular peer.
     *
     * The message is called continuously
     * (e.g. for every packet that must be encrypted, until a key becomes available)
     */
    #[inline(always)]
    async fn need_key(peer: &Self::Opaque) {
        tracing::trace!("{} : EVENT(need_key)", peer);
        peer.packet_send_queued_handshake_initiation(false).await;
    }

    #[inline(always)]
    async fn key_confirmed(peer: &Self::Opaque) {
        tracing::trace!("{} : EVENT(key_confirmed)", peer);
        peer.timers_handshake_complete().await;
    }
}
