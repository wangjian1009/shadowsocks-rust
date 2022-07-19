use bytes::Bytes;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::io;
use std::{collections::HashMap, io::Error as IoError, net::SocketAddr, sync::Arc};
use tokio::sync::mpsc::{self, Receiver, Sender};

use super::super::super::protocol::Address;
use super::super::{UdpSocket, UdpSocketCreator};

#[derive(Clone)]
pub struct UdpPacketFrom(Arc<AtomicCell<Option<UdpPacketSource>>>);

impl UdpPacketFrom {
    pub fn new() -> Self {
        Self(Arc::new(AtomicCell::new(None)))
    }

    pub fn check(&self) -> Option<UdpPacketSource> {
        self.0.load()
    }

    pub fn uni_stream(&self) -> bool {
        self.0
            .compare_exchange(None, Some(UdpPacketSource::UniStream))
            .map_or_else(|from| from == Some(UdpPacketSource::UniStream), |_| true)
    }

    pub fn datagram(&self) -> bool {
        self.0
            .compare_exchange(None, Some(UdpPacketSource::Datagram))
            .map_or_else(|from| from == Some(UdpPacketSource::Datagram), |_| true)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum UdpPacketSource {
    UniStream,
    Datagram,
}

pub type SendPacketSender = Sender<(Bytes, Address)>;
pub type SendPacketReceiver = Receiver<(Bytes, Address)>;
pub type RecvPacketSender = Sender<(u32, Bytes, Address)>;
pub type RecvPacketReceiver = Receiver<(u32, Bytes, Address)>;

pub struct UdpSessionMap {
    map: Mutex<HashMap<u32, UdpSession>>,
    recv_pkt_tx_for_clone: RecvPacketSender,
    udp_socket_creator: Arc<Box<dyn UdpSocketCreator>>,
}

impl UdpSessionMap {
    pub fn new(udp_socket_creator: Arc<Box<dyn UdpSocketCreator>>) -> (Self, RecvPacketReceiver) {
        let (recv_pkt_tx, recv_pkt_rx) = mpsc::channel(1);

        (
            Self {
                map: Mutex::new(HashMap::new()),
                recv_pkt_tx_for_clone: recv_pkt_tx,
                udp_socket_creator,
            },
            recv_pkt_rx,
        )
    }

    #[allow(clippy::await_holding_lock)]
    pub async fn send(&self, assoc_id: u32, pkt: Bytes, addr: Address, src_addr: SocketAddr) -> Result<(), IoError> {
        let mut send_pkt_tx = self.map.lock().get(&assoc_id).map(|s| s.0.clone());

        if send_pkt_tx.is_none() {
            log::info!("[{src_addr}] [associate] [{assoc_id}]");

            let assoc = UdpSession::new(
                assoc_id,
                self.recv_pkt_tx_for_clone.clone(),
                src_addr,
                &self.udp_socket_creator,
            )
            .await?;

            send_pkt_tx = Some(assoc.0.clone());

            let mut map = self.map.lock();
            map.insert(assoc_id, assoc);
        };

        match send_pkt_tx.unwrap().send((pkt, addr)).await {
            Ok(()) => {}
            Err(_err) => return Err(io::Error::new(io::ErrorKind::Other, "tuic udp send channel closed")),
        };

        Ok(())
    }

    pub fn dissociate(&self, assoc_id: u32, src_addr: SocketAddr) {
        log::info!("[{src_addr}] [dissociate] [{assoc_id}]");
        self.map.lock().remove(&assoc_id);
    }
}

struct UdpSession(SendPacketSender);

impl UdpSession {
    async fn new(
        assoc_id: u32,
        recv_pkt_tx: RecvPacketSender,
        src_addr: SocketAddr,
        udp_socket_creator: &Box<dyn UdpSocketCreator>,
    ) -> Result<Self, IoError> {
        let socket = Arc::new(udp_socket_creator.create(assoc_id, src_addr.clone()).await?);
        let (send_pkt_tx, send_pkt_rx) = mpsc::channel(1);

        tokio::spawn(async move {
            match tokio::select!(
                res = Self::listen_send_packet(socket.clone(), assoc_id, src_addr.clone(), send_pkt_rx) => res,
                res = Self::listen_receive_packet(socket, assoc_id, recv_pkt_tx) => res,
            ) {
                Ok(()) => (),
                Err(err) => log::warn!("[{src_addr}] [udp-session] [{assoc_id}] {err}"),
            }
        });

        Ok(Self(send_pkt_tx))
    }

    async fn listen_send_packet(
        socket: Arc<Box<dyn UdpSocket>>,
        assoc_id: u32,
        src_addr: SocketAddr,
        mut send_pkt_rx: SendPacketReceiver,
    ) -> Result<(), IoError> {
        while let Some((pkt, addr)) = send_pkt_rx.recv().await {
            match socket.send_to(&pkt, addr).await {
                Ok(()) => {}
                Err(err) => {
                    log::warn!("[{src_addr}] [udp-session] [{assoc_id}] [] --> {err}")
                }
            }

            // match addr {
            //     Address::DomainAddress(hostname, port) => {
            //         socket.send_to(&pkt, (hostname, port)).await?;
            //     }
            //     Address::SocketAddress(addr) => {
            //         socket.send_to(&pkt, addr).await?;
            //     }
            // }
        }

        Ok(())
    }

    async fn listen_receive_packet(
        socket: Arc<Box<dyn UdpSocket>>,
        assoc_id: u32,
        recv_pkt_tx: RecvPacketSender,
    ) -> Result<(), IoError> {
        loop {
            let (pkt, addr) = socket.recv_from().await?;

            match recv_pkt_tx.send((assoc_id, pkt, Address::SocketAddress(addr))).await {
                Ok(()) => {}
                Err(_err) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("tuic udp send back channel closed"),
                    ))
                }
            };
        }
    }
}
