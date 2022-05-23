use super::*;

use shadowsocks::config::TrojanConfig;
use shadowsocks::create_connector_then;
use shadowsocks::transport::{Connector, PacketMutWrite, PacketRead};
use shadowsocks::trojan::{new_trojan_packet_connection, ClientStream};
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
        let stream = create_connector_then!(
            Some(self.context.context()),
            svr_cfg.connector_transport(),
            |connector| {
                let stream = connector
                    .connect_stream(svr_cfg.external_addr(), self.context.connect_opts_ref())
                    .await?;

                let stream = ClientStream::new_packet(stream, svr_trojan_cfg);

                io::Result::Ok(Box::new(stream) as Box<dyn StreamConnection>)
            }
        )?;

        debug!(
            "created udp association for {} <-> {} (proxied) with {:?}",
            self.peer_addr,
            svr_cfg.addr(),
            self.context.connect_opts_ref()
        );

        // CLIENT <- REMOTE
        let (r, w) = new_trojan_packet_connection(stream);

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
