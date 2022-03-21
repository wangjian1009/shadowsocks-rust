use super::*;
use bytes::Bytes;
use shadowsocks::{
    relay::{tcprelay::utils_copy::copy_bidirectional, udprelay::MAXIMUM_UDP_PAYLOAD_SIZE},
    transport::{MutPacketWriter, PacketRead},
    trojan::{new_trojan_packet_connection, protocol},
};

use super::super::udprelay::UdpAssociationContext;
use tokio::sync::mpsc;

use crate::net::UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE;

impl TcpServerClient {
    pub async fn serve_trojan<IS>(self, valid_hash: &[u8], mut stream: MonProxyStream<IS>) -> io::Result<()>
    where
        IS: StreamConnection + 'static,
    {
        let mut request_timeout = None;
        if let Some(base_timeout) = self.request_recv_timeout {
            request_timeout = Some(base_timeout + Duration::from_secs(rand::random::<u64>() % base_timeout.as_secs()));
        }

        let request = match match request_timeout {
            None => protocol::RequestHeader::read_from(&mut stream, valid_hash, None).await,
            Some(d) => {
                match time::timeout(d, protocol::RequestHeader::read_from(&mut stream, valid_hash, None)).await {
                    Ok(r) => r,
                    Err(..) => Err(Socks5Error::IoError(io::ErrorKind::TimedOut.into())),
                }
            }
        } {
            Ok(a) => a,
            Err(Socks5Error::IoError(ref err)) if err.kind() == ErrorKind::UnexpectedEof => {
                debug!(
                    "handshake failed, received EOF before a complete target Address, peer: {}",
                    self.peer_addr
                );
                return Ok(());
            }
            Err(err) => {
                // https://github.com/shadowsocks/shadowsocks-rust/issues/292
                //
                // Keep connection open.
                warn!(
                    "handshake failed, maybe wrong method or key, or under reply attacks. peer: {}, error: {}",
                    self.peer_addr, err
                );

                // Unwrap and get the plain stream.
                // Otherwise it will keep reporting decryption error before reaching EOF.
                //
                // Note: This will drop all data in the decryption buffer, which is no going back.
                let res = ignore_until_end(&mut stream).await;

                trace!(
                    "silent-drop peer: {} is now closing with result {:?}",
                    self.peer_addr,
                    res
                );

                return Ok(());
            }
        };

        match request {
            protocol::RequestHeader::TcpConnect(_, addr) => self.serve_trojan_tcp(addr, stream).await,
            protocol::RequestHeader::UdpAssociate(_) => self.serve_trojan_udp(stream).await,
        }
    }

    async fn serve_trojan_tcp<IS: StreamConnection>(
        self,
        target_addr: Address,
        mut stream: MonProxyStream<IS>,
    ) -> io::Result<()> {
        let connection_stat = self.context.connection_stat();

        trace!(
            "trojan accepted tcp client connection {}, establishing tunnel to {}",
            self.peer_addr,
            target_addr
        );

        #[cfg(feature = "server-mock")]
        match self.context.mock_server_protocol(&target_addr) {
            Some(protocol) => match protocol {
                ServerMockProtocol::DNS => {
                    let (mut r, mut w) = tokio::io::split(stream);
                    run_dns_tcp_stream(
                        self.context.dns_resolver(),
                        &self.peer_addr,
                        &target_addr,
                        &mut r,
                        &mut w,
                    )
                    .await?;
                    return Ok(());
                }
            },
            None => {}
        }

        if self.context.check_outbound_blocked(&target_addr).await {
            error!(
                "trojan tcp client {} outbound {} blocked by ACL rules",
                self.peer_addr, target_addr
            );
            return Ok(());
        }

        let destination = Destination::Tcp(target_addr.clone().into());

        let mut remote_stream = match timeout_fut(
            self.timeout,
            self.connector.connect(&destination, self.context.connect_opts_ref()),
        )
        .await
        {
            Ok(s) => match s {
                Connection::Stream(s) => s,
                Connection::Packet { .. } => unreachable!(),
            },
            Err(err) => {
                error!(
                    "trojan tcp tunnel {} -> {} connect failed, error: {}",
                    self.peer_addr, target_addr, err
                );
                return Err(err);
            }
        };

        #[cfg(feature = "rate-limit")]
        remote_stream.set_rate_limit(self.rate_limiter);

        // let mut remote_stream = OutboundTcpStream::from_stream(remote_stream, self.rate_limiter);
        let _out_guard = connection_stat.add_out_connection();

        // https://github.com/shadowsocks/shadowsocks-rust/issues/232
        //
        // Protocols like FTP, clients will wait for servers to send Welcome Message without sending anything.
        //
        // Wait at most 500ms, and then sends handshake packet to remote servers.
        if self.context.connect_opts_ref().tcp.fastopen {
            let mut buffer = [0u8; 8192];
            match time::timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    // EOF. Just terminate right here.
                    return Ok(());
                }
                Ok(Ok(n)) => {
                    // Send the first packet.
                    timeout_fut(self.timeout, remote_stream.write_all(&buffer[..n])).await?;
                }
                Ok(Err(err)) => return Err(err),
                Err(..) => {
                    // Timeout. Send handshake to server.
                    timeout_fut(self.timeout, remote_stream.write(&[])).await?;

                    trace!(
                        "trojan tcp tunnel {} -> {} sent TFO connect without data",
                        self.peer_addr,
                        target_addr
                    );
                }
            }
        }

        debug!(
            "trojan established tcp tunnel {} <-> {} with {:?}",
            self.peer_addr,
            target_addr,
            self.context.connect_opts_ref()
        );

        match copy_bidirectional(&mut stream, &mut remote_stream, &self.idle_timeout).await {
            Ok((rn, wn)) => {
                trace!(
                    "trojan tcp tunnel {} <-> {} closed, L2R {} bytes, R2L {} bytes",
                    self.peer_addr,
                    target_addr,
                    rn,
                    wn
                );
            }
            Err(err) => {
                trace!(
                    "trojan tcp tunnel {} <-> {} closed with error: {}",
                    self.peer_addr,
                    target_addr,
                    err
                );
            }
        }

        Ok(())
    }

    async fn serve_trojan_udp<IS>(self, stream: MonProxyStream<IS>) -> io::Result<()>
    where
        IS: StreamConnection + 'static,
    {
        let (mut reader, writer) = new_trojan_packet_connection(stream);

        let (keepalive_tx, mut keepalive_rx) = mpsc::channel(UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE);

        let (_context, sender) = UdpAssociationContext::create(
            self.context.clone(),
            Arc::new(Box::new(MutPacketWriter::new(writer, 1024))),
            self.peer_addr,
            keepalive_tx,
        );

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            tokio::select! {
                peer_addr_opt = keepalive_rx.recv() => {
                    let _peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectly");
                    trace!("vless udp relay {} <- keepalive", self.peer_addr);
                }

                received = reader.read_from(&mut buffer) => {
                    let (n, addr) = received?;

                    trace!("trojan udp relay {} <- {} received {} bytes", self.peer_addr, addr, n);

                    let data = &buffer[..n];

                    let target_addr = Address::from(addr.clone());

                    if let Err(..) = sender.try_send((target_addr, Bytes::copy_from_slice(data))) {
                        let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
                        return Err(err);
                    }

                    trace!(
                        "trojan udp relay {} <- {} with {} bytes",
                        self.peer_addr,
                        addr,
                        data.len()
                    );
                }
            }
        }
    }
}
