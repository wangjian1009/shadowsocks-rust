use shadowsocks::{
    relay::tcprelay::utils_copy::copy_bidirectional,
    vless::{protocol, InboundHandler, VlessUdpReader, VlessUdpWriter},
};

use super::*;

impl TcpServerClient {
    pub async fn serve_vless<IS>(self, inbound: Arc<InboundHandler>, stream: MonProxyStream<IS>) -> io::Result<()>
    where
        IS: StreamConnection + 'static,
    {
        let arc_self = Arc::new(self);

        let mut request_timeout = None;
        if let Some(base_timeout) = arc_self.request_recv_timeout {
            request_timeout = Some(base_timeout + Duration::from_secs(rand::random::<u64>() % base_timeout.as_secs()));
        }

        inbound
            .serve(
                stream,
                &arc_self.peer_addr,
                request_timeout,
                {
                    let arc_self = arc_self.clone();
                    move |s, addr| arc_self.clone().serve_vless_tcp(s, addr)
                },
                {
                    let arc_self = arc_self.clone();
                    move |r, w, addr| arc_self.clone().serve_vless_udp(r, w, addr)
                },
                {
                    let arc_self = arc_self.clone();
                    move |s, err| arc_self.serve_vless_err(s, err)
                },
            )
            .await
    }

    async fn serve_vless_tcp(
        self: Arc<Self>,
        mut stream: Box<dyn StreamConnection>,
        target_addr: Address,
    ) -> io::Result<()> {
        let connection_stat = self.context.connection_stat();

        trace!(
            "vless accepted tcp client connection {}, establishing tunnel to {}",
            self.peer_addr,
            target_addr
        );

        #[cfg(feature = "server-mock")]
        match self.context.mock_server_protocol(&target_addr) {
            Some(protocol) => match protocol {
                ServerMockProtocol::DNS => {
                    let (mut r, mut w) = tokio::io::split(stream);
                    run_dns_tcp_stream(self.context.dns_resolver(), &mut r, &mut w, None).await?;
                    return Ok(());
                }
            },
            None => {}
        }

        if self.context.check_outbound_blocked(&target_addr).await {
            error!(
                "vless tcp client {} outbound {} blocked by ACL rules",
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
                    "vless tcp tunnel {} -> {} connect failed, error: {}",
                    self.peer_addr, target_addr, err
                );
                return Err(err);
            }
        };

        #[cfg(feature = "rate-limit")]
        remote_stream.set_rate_limit(self.rate_limiter.clone());

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
                        "vless tcp tunnel {} -> {} sent TFO connect without data",
                        self.peer_addr,
                        target_addr
                    );
                }
            }
        }

        debug!(
            "vless established tcp tunnel {} <-> {} with {:?}",
            self.peer_addr,
            target_addr,
            self.context.connect_opts_ref()
        );

        let (rn, wn, r) = copy_bidirectional(&mut stream, &mut remote_stream, self.idle_timeout.clone()).await;
        match r {
            Ok(()) => {
                trace!(
                    "vless tcp tunnel {} <-> {} closed, L2R {} bytes, R2L {} bytes",
                    self.peer_addr,
                    target_addr,
                    rn,
                    wn
                );
            }
            Err(err) => {
                trace!(
                    "vless tcp tunnel {} <-> {} closed with error: {}, L2R {} bytes, R2L {} bytes",
                    self.peer_addr,
                    target_addr,
                    err,
                    rn,
                    wn,
                );
            }
        }

        Ok(())
    }

    async fn serve_vless_udp(
        self: Arc<Self>,
        reader: VlessUdpReader<Box<dyn StreamConnection + 'static>>,
        writer: VlessUdpWriter<Box<dyn StreamConnection + 'static>>,
        address: protocol::Address,
    ) -> io::Result<()> {
        super::super::udprelay::vless::serve_vless_udp(self.context.clone(), &self.peer_addr, address, reader, writer)
            .await
    }

    async fn serve_vless_err<IS>(self: Arc<Self>, mut stream: IS, err: io::Error) -> io::Result<()>
    where
        IS: StreamConnection + 'static,
    {
        if err.kind() == ErrorKind::UnexpectedEof {
        } else {
            let res = ignore_until_end(&mut stream).await;

            trace!(
                "silent-drop peer: {} is now closing with result {:?}",
                self.peer_addr,
                res
            );
        }

        Ok(())
    }
}
