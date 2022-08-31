use super::*;
use tokio::sync::mpsc::error::TrySendError;

use crate::local::loadbalancing::ServerIdent;
use crate::net::UDP_ASSOCIATION_SEND_CHANNEL_SIZE;

use shadowsocks::tuic::client as tuic;
use tuic::{Address as RelayAddress, AssociateRecvPacketReceiver, AssociateSendPacketSender, Request};

pub struct TuicUdpContext {
    packet_sender: AssociateSendPacketSender,
    packet_receiver: AssociateRecvPacketReceiver,
    #[cfg(not(feature = "tuic-global"))]
    _dispatcher: Arc<tuic::Dispatcher>,
}

impl TuicUdpContext {
    pub async fn tuic_receive_from(
        &mut self,
        peer_addr: &SocketAddr,
        buf: &mut Vec<u8>,
    ) -> io::Result<(usize, Address, Option<UdpSocketControlData>)> {
        let (bytes, addr) = match self.packet_receiver.recv().await {
            Some(v) => v,
            None => {
                log::error!(
                    "udp relay {} <- ... (tuic) failed, error: receiver chanel break",
                    peer_addr,
                );
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        };

        let origin_len = bytes.len();
        let recv_len = std::cmp::min(origin_len, buf.len());

        if origin_len > recv_len {
            log::error!(
                "udp relay {} <- {} (vless) receive packet overflow, input-len={}, capacity={}",
                peer_addr,
                addr,
                origin_len,
                buf.len(),
            );
        }

        buf[..recv_len].copy_from_slice(&bytes[..recv_len]);

        Ok((
            recv_len,
            match addr {
                RelayAddress::DomainAddress(name, port) => Address::DomainNameAddress(name, port),
                RelayAddress::SocketAddress(addr) => Address::SocketAddress(addr),
            },
            None,
        ))
    }

    pub fn tuic_try_send_to(
        self: &mut TuicUdpContext,
        _peer_addr: &SocketAddr,
        target_addr: &Address,
        data: &[u8],
    ) -> io::Result<()> {
        match self.packet_sender.try_send((
            Bytes::copy_from_slice(data),
            match target_addr {
                Address::DomainNameAddress(domain, port) => RelayAddress::DomainAddress(domain.clone(), port.clone()),
                Address::SocketAddress(addr) => RelayAddress::SocketAddress(addr.clone()),
            },
        )) {
            Ok(()) => {}
            Err(err) => match err {
                TrySendError::Closed(..) => return Err(io::Error::new(io::ErrorKind::Other, "tuic channel closed")),
                TrySendError::Full(..) => return Err(io::Error::new(io::ErrorKind::Other, "tuic send channel full")),
            },
        }
        Ok(())
    }
}

impl<W> UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    pub async fn tuic_create_context(
        &self,
        server: &ServerIdent,
        _tuic_cfg: &shadowsocks::config::TuicConfig,
    ) -> io::Result<MultiProtocolProxySocket> {
        let (relay_req, pkt_send_tx, pkt_recv_rx) = Request::new_associate(UDP_ASSOCIATION_SEND_CHANNEL_SIZE);

        #[cfg(not(feature = "tuic-global"))]
        let dispatcher = {
            let tuic_config = match _tuic_cfg {
                shadowsocks::config::TuicConfig::Client(c) => c,
                shadowsocks::config::TuicConfig::Server(..) => unreachable!(),
            };

            let server_addr = match server.server_config().addr() {
                shadowsocks::ServerAddr::DomainName(domain, port) => tuic::ServerAddr::DomainAddr {
                    domain: domain.clone(),
                    port: port.clone(),
                },
                shadowsocks::ServerAddr::SocketAddr(addr) => {
                    let sni = match tuic_config.sni.as_ref() {
                        Some(sni) => sni,
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "server sni is not spected",
                            ))
                        }
                    };
                    tuic::ServerAddr::SocketAddr {
                        addr: addr.clone(),
                        name: sni.clone(),
                    }
                }
            };

            let config = tuic::Config::new(tuic_config)?;

            let dispatcher = Arc::new(tuic::Dispatcher::new(
                self.context.context(),
                server_addr,
                config,
                self.context.connect_opts_ref().clone(),
            ));

            dispatcher.clone().send_req(relay_req).await?;

            dispatcher
        };

        #[cfg(feature = "tuic-global")]
        server.tuic_dispatcher().unwrap().send_req(relay_req).await?;

        Ok(MultiProtocolProxySocket::Tuic(TuicUdpContext {
            packet_sender: pkt_send_tx,
            packet_receiver: pkt_recv_rx,
            #[cfg(not(feature = "tuic-global"))]
            _dispatcher: dispatcher,
        }))
    }
}
