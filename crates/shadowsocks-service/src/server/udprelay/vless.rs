use super::*;

use shadowsocks::transport::StreamConnection;
use shadowsocks::vless;
use shadowsocks::ServerAddr;

pub type VlessUdpWriter = vless::VlessUdpWriter<Box<dyn StreamConnection + 'static>>;
pub type VlessUdpReader = vless::VlessUdpReader<Box<dyn StreamConnection + 'static>>;

pub async fn serve_vless_udp(
    context: Arc<ServiceContext>,
    peer_addr: &SocketAddr,
    target_address: ServerAddr,
    mut reader: VlessUdpReader,
    writer: VlessUdpWriter,
) -> io::Result<()> {
    let (keepalive_tx, mut keepalive_rx) = mpsc::channel(UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE);

    let sender = UdpAssociation::new_association(
        context,
        MultiProtocolSocket::Vless(writer),
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

            received = reader.read_from(&mut buffer) => {
                let n = received?;

                trace!("vless udp relay {} <- {} received {} bytes", peer_addr, target_address, n);

                let data = &buffer[..n];

                if let Err(..) = sender.try_send((peer_addr.clone(), target_address.clone(), Bytes::copy_from_slice(data), None)) {
                    let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
                    return Err(err);
                }

                trace!(
                    "vless udp relay {} <- {} with {} bytes",
                    peer_addr,
                    target_address,
                    data.len()
                );
            }
        }
    }
}
