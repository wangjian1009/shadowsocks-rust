use super::*;

use crate::local::loadbalancing::ServerIdent;

use bytes::Buf;
use shadowsocks::{
    create_connector_then,
    vless::{self, new_vless_packet_connection, protocol, ClientStream},
};

type VlessUdpWriter = vless::VlessUdpWriter<Box<dyn StreamConnection>>;

type VlessAssociationMap = LruCache<Address, VlessUdpAssoiation>;

pub struct VlessUdpAssoiation {
    w: VlessUdpWriter,
    r2l_task: JoinHandle<io::Result<()>>,
}

impl Drop for VlessUdpAssoiation {
    fn drop(&mut self) {
        self.r2l_task.abort()
    }
}

pub struct VlessUdpContext {
    context: Arc<ServiceContext>,
    server: Arc<ServerIdent>,
    assoc_map: VlessAssociationMap,
    packet_sender: Arc<mpsc::Sender<(Address, Bytes)>>,
    packet_receiver: mpsc::Receiver<(Address, Bytes)>,
}

impl<W> UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    pub async fn vless_create_context(
        &self,
        context: Arc<ServiceContext>,
        server: Arc<ServerIdent>,
        time_to_live: Duration,
    ) -> io::Result<MultiProtocolProxySocket> {
        let (packet_sender, packet_receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_CHANNEL_SIZE);

        let packet_sender = Arc::new(packet_sender);

        let context = VlessUdpContext {
            context,
            server,
            assoc_map: LruCache::with_expiry_duration(time_to_live),
            packet_sender,
            packet_receiver,
        };
        Ok(MultiProtocolProxySocket::Vless(context))
    }
}

impl VlessUdpContext {
    pub async fn vless_send_to(
        self: &mut VlessUdpContext,
        peer_addr: &SocketAddr,
        target_addr: &Address,
        data: &[u8],
    ) -> io::Result<()> {
        if let Some(assoc) = self.assoc_map.get_mut(target_addr) {
            match assoc.w.write_to_mut(data).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    debug!("udp relay {} -> {} (vless) send error, {}", peer_addr, target_addr, err);
                }
            }
        }

        // use futures::TryFutureExt;
        let svr_cfg = self.server.server_config();
        #[allow(unused_mut)]
        let mut svr_vless_cfg = match svr_cfg.protocol() {
            ServerProtocol::Vless(c) => c,
            _ => unreachable!(),
        };

        #[cfg(feature = "local-fake-mode")]
        let mut _vless_cfg_buf = None;

        #[cfg(feature = "local-fake-mode")]
        {
            let fake_mode = self.context.fake_mode();
            if let Some(fake_cfg) = fake_mode.is_param_error_for_vless(svr_vless_cfg) {
                _vless_cfg_buf = Some(fake_cfg);
                svr_vless_cfg = _vless_cfg_buf.as_ref().unwrap();
            }
        }

        let (mut r, w) = create_connector_then!(
            Some(self.context.context()),
            svr_cfg.connector_transport(),
            |connector| {
                let stream = ClientStream::connect(
                    &connector,
                    svr_cfg,
                    svr_vless_cfg,
                    protocol::RequestCommand::UDP,
                    ServerAddr::from(target_addr.clone()).into(),
                    self.context.connect_opts_ref(),
                    |f| f,
                )
                .await?;

                // CLIENT <- REMOTE

                let stream = Box::new(stream) as Box<dyn StreamConnection>;
                let (r, w) = new_vless_packet_connection(stream);
                io::Result::Ok((r, w))
            }
        )?;

        debug!(
            "created udp association for {} <-> {} <-> {} (proxied, added) with {:?}",
            peer_addr,
            svr_cfg.addr(),
            target_addr,
            self.context.connect_opts_ref()
        );

        let packet_sender = self.packet_sender.clone();
        let peer_addr = peer_addr.clone();
        let r2l_task = {
            let target_addr = target_addr.clone();
            tokio::spawn(
                async move {
                    let mut buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
                    loop {
                        let size = r.read_from(&mut buf).await?;

                        match packet_sender
                            .send((target_addr.clone(), Bytes::copy_from_slice(&buf[..size])))
                            .await
                        {
                            Ok(()) => (),
                            Err(err) => {
                                tracing::error!(
                                    "udp relay {} <- {} (vless) : send to channel error {}",
                                    peer_addr,
                                    target_addr,
                                    err
                                );
                            }
                        };
                    }
                }
                .in_current_span(),
            )
        };

        let mut assoc = VlessUdpAssoiation { w, r2l_task };

        match assoc.w.write_to_mut(data).await {
            Ok(()) => {}
            Err(err) => {
                debug!("udp relay {} -> {} (vless) send error, {}", peer_addr, target_addr, err);
                return Err(err);
            }
        }

        let _ = self.assoc_map.insert(target_addr.clone(), assoc);

        Ok(())
    }

    pub async fn vless_receive_from(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> io::Result<(usize, Address, Option<UdpSocketControlData>)> {
        let (addr, mut bytes) = match self.packet_receiver.recv().await {
            Some(v) => v,
            None => {
                tracing::error!("<- ... (vless) failed, error: receiver chanel break",);
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        };

        let origin_len = bytes.remaining();
        let recv_len = std::cmp::min(origin_len, buf.len());

        if origin_len > recv_len {
            tracing::error!(
                "<- {} (vless) receive packet overflow, input-len={}, capacity={}",
                addr,
                origin_len,
                buf.len(),
            );
        }

        bytes.copy_to_slice(&mut buf[..recv_len]);

        Ok((recv_len, addr, None))
    }
}
