use std::{
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use etherparse::PacketBuilder;
use shadowsocks::{relay::socks5::Address, canceler::Canceler};
use tokio::sync::mpsc;
use tracing::debug;

use crate::{
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::{UdpAssociationCloseReason, UdpAssociationCloseReceiver, UdpAssociationManager, UdpInboundWrite},
    },
    net::utils::to_ipv4_mapped,
};

pub struct UdpTun {
    tun_rx: mpsc::Receiver<BytesMut>,
    manager: UdpAssociationManager<UdpTunInboundWriter>,
}

impl UdpTun {
    pub fn new(
        context: Arc<ServiceContext>,
        balancer: PingBalancer,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
    ) -> (UdpTun, UdpAssociationCloseReceiver) {
        let (tun_tx, tun_rx) = mpsc::channel(64);
        let (manager, close_rx) = UdpAssociationManager::new(
            context,
            UdpTunInboundWriter::new(tun_tx),
            time_to_live,
            capacity,
            balancer,
        );

        (UdpTun { tun_rx, manager }, close_rx)
    }

    pub fn manager(&self) -> &UdpAssociationManager<UdpTunInboundWriter> {
        &self.manager
    }

    pub fn close_association(&mut self, peer_addr: &SocketAddr, reason: UdpAssociationCloseReason) {
        self.manager.close_association(peer_addr, reason)
    }

    pub async fn handle_packet(
        &mut self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
        canceler: &Arc<Canceler>,
    ) -> io::Result<()> {
        debug!("UDP {} -> {} payload.size: {} bytes", src_addr, dst_addr, payload.len());
        if let Err(err) = self.manager.send_to(src_addr, dst_addr.into(), payload, canceler).await {
            debug!(
                "UDP {} -> {} payload.size: {} bytes failed, error: {}",
                src_addr,
                dst_addr,
                payload.len(),
                err,
            );
        }
        Ok(())
    }

    pub async fn recv_packet(&mut self) -> BytesMut {
        match self.tun_rx.recv().await {
            Some(b) => b,
            None => unreachable!("channel closed unexpectedly"),
        }
    }

    // #[inline(always)]
    // pub async fn cleanup_expired(&mut self) {
    //     self.manager.cleanup_expired().await;
    // }

    // #[inline(always)]
    // pub async fn keep_alive(&mut self, peer_addr: &SocketAddr) {
    //     self.manager.keep_alive(peer_addr).await;
    // }
}

#[derive(Clone)]
pub struct UdpTunInboundWriter {
    tun_tx: mpsc::Sender<BytesMut>,
}

impl UdpTunInboundWriter {
    fn new(tun_tx: mpsc::Sender<BytesMut>) -> UdpTunInboundWriter {
        UdpTunInboundWriter { tun_tx }
    }
}

#[async_trait]
impl UdpInboundWrite for UdpTunInboundWriter {
    async fn send_to(
        &self,
        peer_addr: SocketAddr,
        remote_addr: &Address,
        data: &[u8],
        canceler: &Canceler,
    ) -> io::Result<()> {
        let addr = match *remote_addr {
            Address::SocketAddress(sa) => {
                // Try to convert IPv4 mapped IPv6 address if server is running on dual-stack mode
                match (peer_addr, sa) {
                    (SocketAddr::V4(..), SocketAddr::V4(..)) | (SocketAddr::V6(..), SocketAddr::V6(..)) => sa,
                    (SocketAddr::V4(..), SocketAddr::V6(v6)) => {
                        // If peer is IPv4, then remote_addr can only be IPv4-mapped-IPv6
                        match to_ipv4_mapped(v6.ip()) {
                            Some(v4) => SocketAddr::new(IpAddr::from(v4), v6.port()),
                            None => {
                                return Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "source and destination type unmatch",
                                ));
                            }
                        }
                    }
                    (SocketAddr::V6(..), SocketAddr::V4(v4)) => {
                        // Convert remote_addr to IPv4-mapped-IPv6
                        SocketAddr::new(IpAddr::from(v4.ip().to_ipv6_mapped()), v4.port())
                    }
                }
            }
            Address::DomainNameAddress(..) => {
                let err = io::Error::new(
                    ErrorKind::InvalidInput,
                    "tun destination must not be an domain name address",
                );
                return Err(err);
            }
        };

        let packet = match (peer_addr, addr) {
            (SocketAddr::V4(peer), SocketAddr::V4(remote)) => {
                let builder =
                    PacketBuilder::ipv4(remote.ip().octets(), peer.ip().octets(), 20).udp(remote.port(), peer.port());

                let packet = BytesMut::with_capacity(builder.size(data.len()));
                let mut packet_writer = packet.writer();

                if let Err(err) = builder.write(&mut packet_writer, data) {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("PacketBuilder::write failed: {:?}", err),
                    ));
                }

                packet_writer.into_inner()
            }
            (SocketAddr::V6(peer), SocketAddr::V6(remote)) => {
                let builder =
                    PacketBuilder::ipv6(remote.ip().octets(), peer.ip().octets(), 20).udp(remote.port(), peer.port());

                let packet = BytesMut::with_capacity(builder.size(data.len()));
                let mut packet_writer = packet.writer();

                if let Err(err) = builder.write(&mut packet_writer, data) {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("PacketBuilder::write failed: {:?}", err),
                    ));
                }

                packet_writer.into_inner()
            }
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "source and destination type unmatch",
                ));
            }
        };

        let mut waiter = canceler.waiter();
        tokio::select! {
            r =  self.tun_tx.send(packet) => {
                r.map_err(|e| io::Error::new(ErrorKind::Other, format!("failed to send packet to tun: {}", e)))?;
            }
            _ = waiter.wait() => {
                return Err(io::Error::new(io::ErrorKind::Other, "send_to canceled"));
            }
        }

        Ok(())
    }
}
