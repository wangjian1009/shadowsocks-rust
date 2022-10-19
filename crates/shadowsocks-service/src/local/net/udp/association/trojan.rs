use super::*;

use shadowsocks::config::TrojanConfig;
use shadowsocks::create_connector_then;
use shadowsocks::transport::{PacketMutWrite, PacketRead};
use shadowsocks::trojan::client::connect_packet;
use shadowsocks::ServerAddr;

pub type TrojanUdpReader = shadowsocks::trojan::TrojanUdpReader<Box<dyn StreamConnection>>;
pub type TrojanUdpWriter = shadowsocks::trojan::TrojanUdpWriter<Box<dyn StreamConnection>>;

impl<W> UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    pub async fn trojan_connect(
        &self,
        svr_cfg: &ServerConfig,
        svr_trojan_cfg: &TrojanConfig,
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

        debug!(
            "created udp association for {} <-> {} (proxied) with {:?}",
            self.peer_addr,
            svr_cfg.addr(),
            self.context.connect_opts_ref()
        );

        Ok(MultiProtocolProxySocket::Trojan { r, w })
    }
}

pub async fn trojan_send_to(socket: &mut TrojanUdpWriter, target_addr: &Address, data: &[u8]) -> io::Result<()> {
    let target_addr = ServerAddr::from(target_addr);
    socket.write_to_mut(data, &target_addr).await
}

pub async fn trojan_receive_from(
    socket: &mut TrojanUdpReader,
    buf: &mut Vec<u8>,
) -> io::Result<(usize, Address, Option<UdpSocketControlData>)> {
    let (sz, addr) = socket.read_from(buf).await?;
    Ok((sz, Address::from(addr), None))
}
