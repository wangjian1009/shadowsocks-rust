use super::*;

use shadowsocks::{
    transport::{PacketRead, StreamConnection},
    trojan::new_trojan_packet_connection,
};

pub type TrojanUdpWriter = shadowsocks::trojan::TrojanUdpWriter<Box<dyn StreamConnection>>;

pub async fn serve_trojan_udp<IS>(context: Arc<ServiceContext>, peer_addr: SocketAddr, stream: IS) -> io::Result<()>
where
    IS: StreamConnection + 'static,
{
    let stream = Box::new(stream) as Box<dyn StreamConnection>;
    let (mut inbound_reader, inbound_writer) = new_trojan_packet_connection(stream);

    let (keepalive_tx, mut keepalive_rx) = mpsc::channel(UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE);

    let sender = UdpAssociation::new_association(
        context,
        MultiProtocolSocket::Trojan(inbound_writer),
        peer_addr.clone(),
        keepalive_tx,
    );

    let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
    loop {
        tokio::select! {
            peer_addr_opt = keepalive_rx.recv() => {
                let _peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectly");
                trace!("vless udp relay {} <- keepalive", peer_addr);
            }

            received = inbound_reader.read_from(&mut buffer) => {
                let (n, addr) = received?;

                trace!("trojan udp relay {} <- {} received {} bytes", peer_addr, addr, n);

                let data = &buffer[..n];

                let target_addr = Address::from(addr.clone());

                if let Err(..) = sender.try_send((peer_addr.clone(), target_addr, Bytes::copy_from_slice(data), None)) {
                    let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
                    return Err(err);
                }

                trace!(
                    "trojan udp relay {} <- {} with {} bytes",
                    peer_addr,
                    addr,
                    data.len()
                );
            }
        }
    }
}
