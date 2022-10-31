use super::*;
use tokio::sync::{mpsc::error::TrySendError, Notify};

use crate::local::loadbalancing::ServerIdent;
use crate::net::UDP_ASSOCIATION_SEND_CHANNEL_SIZE;

use shadowsocks::tuic::client as tuic;
use shadowsocks::ServerAddr;
use tuic::{AssociateRecvPacketReceiver, AssociateSendPacketSender, Request};

pub struct TuicUdpContext {
    packet_sender: AssociateSendPacketSender,
    packet_receiver: AssociateRecvPacketReceiver,
}

impl TuicUdpContext {
    pub async fn tuic_receive_from(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> Result<(usize, Address, Option<UdpSocketControlData>), UdpAssociationCloseReason> {
        let (bytes, addr) = match self.packet_receiver.recv().await {
            Some(v) => v,
            None => {
                debug!("tuic packet receive chanel break");
                return Err(UdpAssociationCloseReason::InternalError);
            }
        };

        let origin_len = bytes.len();
        let recv_len = std::cmp::min(origin_len, buf.len());

        if origin_len > recv_len {
            error!(
                target = addr.to_string(),
                "tuic packet overflow, input-len={}, capacity={}", origin_len, recv_len,
            );
        }

        buf[..recv_len].copy_from_slice(&bytes[..recv_len]);

        Ok((recv_len, Address::from(addr), None))
    }

    pub fn tuic_try_send_to(
        self: &mut TuicUdpContext,
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
                    error!(error = ?err, "tuic channel closed");
                    Err(UdpAssociationCloseReason::InternalError)
                }
                TrySendError::Full(..) => {
                    debug!(error = ?err, "tuic send channel full");
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
    pub async fn tuic_create_context(
        &self,
        server: &ServerIdent,
        close_notify: Option<Arc<Notify>>,
        _tuic_cfg: &shadowsocks::config::TuicConfig,
    ) -> io::Result<MultiProtocolProxySocket> {
        let (relay_req, pkt_send_tx, pkt_recv_rx) = Request::new_associate(UDP_ASSOCIATION_SEND_CHANNEL_SIZE);

        server
            .tuic_dispatcher()
            .unwrap()
            .send_req(relay_req, close_notify)
            .await?;

        Ok(MultiProtocolProxySocket::Tuic(TuicUdpContext {
            packet_sender: pkt_send_tx,
            packet_receiver: pkt_recv_rx,
        }))
    }
}
