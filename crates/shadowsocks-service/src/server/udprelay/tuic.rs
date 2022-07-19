use async_trait::async_trait;
use tokio::sync::mpsc::{self, Receiver, Sender};

use super::*;

use shadowsocks::{net::UdpSocket as OutboundUdpSocket, tuic};

pub struct TuicUdpSocket {
    context: Arc<ServiceContext>,
    max_udp_packet_size: usize,
    peer_addr: SocketAddr,
    assoc_id: u32,
    outbound_ipv4_socket: spin::Mutex<Option<Arc<OutboundUdpSocket>>>,
    outbound_ipv6_socket: spin::Mutex<Option<Arc<OutboundUdpSocket>>>,
    socket_update_tx: Sender<()>,
    socket_update_rx: tokio::sync::Mutex<Receiver<()>>,
}

impl TuicUdpSocket {
    async fn send_to_sock_addr(&self, mut target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        const UDP_SOCKET_SUPPORT_DUAL_STACK: bool = cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "freebsd",
            // target_os = "dragonfly",
            // target_os = "netbsd",
            target_os = "windows",
        ));

        let mut socket_updated = false;

        let socket = if UDP_SOCKET_SUPPORT_DUAL_STACK {
            let mut outbound_ipv6_socket = self.outbound_ipv6_socket.lock();
            match *outbound_ipv6_socket {
                Some(ref socket) => socket.clone(),
                None => {
                    let socket =
                        OutboundUdpSocket::connect_any_with_opts(AddrFamily::Ipv6, self.context.connect_opts_ref())
                            .await?;

                    log::debug!(
                        "[{}] [udp-session] [{}] socket ipv6 created",
                        self.peer_addr,
                        self.assoc_id
                    );

                    socket_updated = true;
                    outbound_ipv6_socket.insert(Arc::new(socket)).clone()
                }
            }
        } else {
            match target_addr {
                SocketAddr::V4(..) => {
                    let mut outbound_ipv4_socket = self.outbound_ipv4_socket.lock();
                    match *outbound_ipv4_socket {
                        Some(ref socket) => socket.clone(),
                        None => {
                            let socket =
                                OutboundUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref())
                                    .await?;

                            log::debug!(
                                "[{}] [udp-session] [{}] socket ipv4 created",
                                self.peer_addr,
                                self.assoc_id
                            );

                            socket_updated = true;
                            outbound_ipv4_socket.insert(Arc::new(socket)).clone()
                        }
                    }
                }
                SocketAddr::V6(..) => {
                    let mut outbound_ipv6_socket = self.outbound_ipv6_socket.lock();
                    match *outbound_ipv6_socket {
                        Some(ref socket) => socket.clone(),
                        None => {
                            let socket =
                                OutboundUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref())
                                    .await?;

                            log::debug!(
                                "[{}] [udp-session] [{}] socket ipv6 created",
                                self.peer_addr,
                                self.assoc_id
                            );

                            socket_updated = true;
                            outbound_ipv6_socket.insert(Arc::new(socket)).clone()
                        }
                    }
                }
            }
        };

        if socket_updated {
            self.socket_update_tx
                .send(())
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("notify reader sock update error {}", e)))?;
        }

        if UDP_SOCKET_SUPPORT_DUAL_STACK {
            if let SocketAddr::V4(saddr) = target_addr {
                let mapped_ip = saddr.ip().to_ipv6_mapped();
                target_addr = SocketAddr::V6(SocketAddrV6::new(mapped_ip, saddr.port(), 0, 0));
            }
        }

        let n = socket.send_to(data, target_addr).await?;
        if n != data.len() {
            warn!(
                "[{}] [udp-session] [{}] {target_addr} --> {n} bytes mismatch, expected {} bytes",
                self.peer_addr,
                self.assoc_id,
                data.len()
            );
        } else {
            log::debug!(
                "[{}] [udp-session] [{}] {target_addr} --> {n} bytes",
                self.peer_addr,
                self.assoc_id,
            );
        }

        Ok(())
    }
}

#[async_trait]
impl tuic::server::UdpSocket for TuicUdpSocket {
    async fn recv_from(&self) -> io::Result<(Bytes, SocketAddr)> {
        #[inline]
        async fn receive_from_outbound_opt(
            socket: &Option<Arc<OutboundUdpSocket>>,
            peer_addr: &SocketAddr,
            assoc_id: u32,
            max_udp_packet_size: usize,
        ) -> io::Result<(Bytes, SocketAddr)> {
            match *socket {
                None => unreachable!(),
                Some(ref s) => {
                    let mut buf = vec![0; max_udp_packet_size];
                    let (len, addr) = s.recv_from(&mut buf).await?;
                    buf.truncate(len);

                    log::debug!("[{}] [udp-session] [{}] {addr} <-- {len} bytes", peer_addr, assoc_id,);

                    Ok((Bytes::from(buf), addr))
                }
            }
        }

        loop {
            let outbound_ipv4_socket = self.outbound_ipv4_socket.lock().clone();
            let outbound_ipv6_socket = self.outbound_ipv6_socket.lock().clone();
            let mut socket_update_rx = self.socket_update_rx.lock().await;

            tokio::select! {
                received_opt = receive_from_outbound_opt(&outbound_ipv4_socket, &self.peer_addr, self.assoc_id, self.max_udp_packet_size)
                    , if outbound_ipv4_socket.is_some() => {
                        return received_opt;
                }
                received_opt = receive_from_outbound_opt(&outbound_ipv6_socket, &self.peer_addr, self.assoc_id, self.max_udp_packet_size)
                    , if outbound_ipv6_socket.is_some() => {
                        return received_opt;
                }
                _socket_updated = socket_update_rx.recv() => {
                    log::debug!(
                        "[{}] [udp-session] [{}] socket updated",
                        self.peer_addr,
                        self.assoc_id,
                    );
                }
            }
        }
    }

    async fn send_to(&self, buf: &[u8], addr: tuic::server::Address) -> io::Result<()> {
        match addr {
            tuic::server::Address::SocketAddress(sa) => self.send_to_sock_addr(sa, buf).await,
            tuic::server::Address::DomainAddress(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |sa| {
                    self.send_to_sock_addr(sa, buf).await
                })
                .map(|_| ())
            }
        }
    }
}

pub struct TuicUdpSocketCreator {
    context: Arc<ServiceContext>,
    max_udp_packet_size: usize,
}

#[async_trait]
impl tuic::server::UdpSocketCreator for TuicUdpSocketCreator {
    async fn create(&self, assoc_id: u32, peer_addr: SocketAddr) -> io::Result<Box<dyn tuic::server::UdpSocket>> {
        let (socket_update_tx, socket_update_rx) = mpsc::channel(1);

        let udp_socket = TuicUdpSocket {
            context: self.context.clone(),
            max_udp_packet_size: self.max_udp_packet_size,
            peer_addr,
            assoc_id,
            outbound_ipv4_socket: spin::Mutex::new(None),
            outbound_ipv6_socket: spin::Mutex::new(None),
            socket_update_tx,
            socket_update_rx: tokio::sync::Mutex::new(socket_update_rx),
        };

        Ok(Box::new(udp_socket) as Box<dyn tuic::server::UdpSocket>)
    }
}

impl TuicUdpSocketCreator {
    pub fn new(context: Arc<ServiceContext>, max_udp_packet_size: usize) -> Self {
        Self {
            context,
            max_udp_packet_size,
        }
    }
}
