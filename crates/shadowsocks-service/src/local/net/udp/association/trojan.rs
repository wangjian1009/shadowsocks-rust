use super::*;

use tokio::{
    sync::mpsc::{self, error::TrySendError, Receiver, Sender},
    task::JoinHandle,
};

use shadowsocks::{
    config::TrojanConfig,
    create_connector_then,
    trojan::{client::connect_packet, TrojanUdpReader, TrojanUdpWriter},
    ServerAddr,
};

use crate::net::UDP_ASSOCIATION_SEND_CHANNEL_SIZE;

use super::UdpAssociationCloseReason;

pub struct TrojanUdpContext {
    packet_sender: Sender<(Bytes, ServerAddr)>,
    packet_receiver: Receiver<(Bytes, ServerAddr)>,
    task: JoinHandle<()>,
}

impl Drop for TrojanUdpContext {
    fn drop(&mut self) {
        self.task.abort()
    }
}

impl TrojanUdpContext {
    fn new<S>(
        r: TrojanUdpReader<S>,
        w: TrojanUdpWriter<S>,
        peer_addr: SocketAddr,
        close_tx: UdpAssociationCloseSender,
    ) -> Self
    where
        S: StreamConnection + 'static,
    {
        // 到远程的请求通过tcp处理，可能有延迟，设置一个较大的缓存处理请求
        let (local_pkg_sender, local_pkg_receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_CHANNEL_SIZE);
        // 到本地的请求延时应该很低，所以使用较小的通道
        let (remote_pkg_sender, remote_pkg_receiver) = mpsc::channel(1);

        let task = tokio::spawn(
            Self::dispatch_packets(local_pkg_receiver, remote_pkg_sender, r, w, peer_addr, close_tx).in_current_span(),
        );

        Self {
            packet_sender: local_pkg_sender,
            packet_receiver: remote_pkg_receiver,
            task,
        }
    }

    async fn dispatch_packets<S>(
        mut local_pkg_receiver: Receiver<(Bytes, ServerAddr)>,
        mut remote_pkg_sender: Sender<(Bytes, ServerAddr)>,
        r: TrojanUdpReader<S>,
        w: TrojanUdpWriter<S>,
        peer_addr: SocketAddr,
        close_tx: UdpAssociationCloseSender,
    ) where
        S: StreamConnection,
    {
        let r = tokio::select! {
            r = Self::dispatch_packets_l2r(&mut local_pkg_receiver, w) => { r }
            r = Self::dispatch_packets_r2l(&mut remote_pkg_sender, r) => { r }
        };

        match close_tx.send((peer_addr, r)).await {
            Ok(()) => {}
            Err(err) => {
                error!(error = ?err, "dispatch_packets: send close reason error");
            }
        }
    }

    async fn dispatch_packets_l2r<S>(
        local_pkg_receiver: &mut Receiver<(Bytes, ServerAddr)>,
        mut w: TrojanUdpWriter<S>,
    ) -> UdpAssociationCloseReason
    where
        S: StreamConnection,
    {
        loop {
            let (data, target) = match local_pkg_receiver.recv().await {
                Some(pkt) => pkt,
                None => {
                    trace!("local_pkg channel closed");
                    return UdpAssociationCloseReason::RemoteSocketError;
                }
            };

            match w.write_to_mut(&data, &target).await {
                Ok(()) => {}
                Err(_err) => {
                    return UdpAssociationCloseReason::RemoteSocketError;
                }
            }
        }
    }

    async fn dispatch_packets_r2l<S>(
        remote_pkg_sender: &mut Sender<(Bytes, ServerAddr)>,
        mut r: TrojanUdpReader<S>,
    ) -> UdpAssociationCloseReason
    where
        S: StreamConnection,
    {
        loop {
            let mut data = vec![0; MAXIMUM_UDP_PAYLOAD_SIZE];
            let (n, addr) = match r.read_from(&mut data).await {
                Ok(r) => r,
                Err(_err) => {
                    trace!("channel closed");
                    return UdpAssociationCloseReason::RemoteSocketError;
                }
            };
            data.truncate(n);
            match remote_pkg_sender.send((Bytes::from(data), addr)).await {
                Ok(()) => {}
                Err(_err) => {
                    debug!("remote_pkt channel closed");
                    return UdpAssociationCloseReason::InternalError;
                }
            }
        }
    }

    pub async fn trojan_receive_from(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> Result<(usize, Address, Option<UdpSocketControlData>), UdpAssociationCloseReason> {
        let (bytes, addr) = match self.packet_receiver.recv().await {
            Some(v) => v,
            None => {
                debug!("trojan packet receive chanel break");
                return Err(UdpAssociationCloseReason::InternalError);
            }
        };

        let origin_len = bytes.len();
        let recv_len = std::cmp::min(origin_len, buf.len());

        if origin_len > recv_len {
            error!(
                target = addr.to_string(),
                "trojan packet overflow, input-len={}, capacity={}", origin_len, recv_len,
            );
        }

        buf[..recv_len].copy_from_slice(&bytes[..recv_len]);

        Ok((recv_len, Address::from(addr), None))
    }

    pub fn trojan_try_send_to(
        self: &mut TrojanUdpContext,
        target_addr: &Address,
        data: &[u8],
    ) -> Result<bool, UdpAssociationCloseReason> {
        match self
            .packet_sender
            .try_send((Bytes::copy_from_slice(data), ServerAddr::from(target_addr.clone())))
        {
            Ok(()) => Ok(true),
            Err(err) => match err {
                TrySendError::Closed(..) => {
                    error!(error = ?err, "trojan channel closed");
                    Err(UdpAssociationCloseReason::InternalError)
                }
                TrySendError::Full(..) => {
                    debug!(error = ?err, "trojan send channel full");
                    Ok(false)
                }
            },
        }
    }
}

impl<W> UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    pub async fn trojan_create_context(
        &self,
        svr_cfg: &ServerConfig,
        svr_trojan_cfg: &TrojanConfig,
        peer_addr: SocketAddr,
        close_tx: UdpAssociationCloseSender,
    ) -> io::Result<MultiProtocolProxySocket> {
        let (r, w) = create_connector_then!(
            Some(self.context.context()),
            svr_cfg.connector_transport(),
            |connector| {
                connect_packet(
                    &connector,
                    svr_cfg,
                    svr_trojan_cfg,
                    self.context.connect_opts_ref(),
                    |s| Box::new(s) as Box<dyn StreamConnection>,
                )
                .await
            }
        )?;

        debug!("udp session established with {:?}", self.context.connect_opts_ref());

        Ok(MultiProtocolProxySocket::Trojan(TrojanUdpContext::new(
            r, w, peer_addr, close_tx,
        )))
    }
}
