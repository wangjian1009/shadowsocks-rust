//! DNS Relay Upstream

#[cfg(unix)]
use std::path::Path;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use log::trace;
use rand::{thread_rng, Rng};
use shadowsocks::{
    config::{ServerConfig, ServerProtocol},
    context::SharedContext,
    net::{ConnectOpts, FlowStat, TcpStream as ShadowTcpStream, UdpSocket as ShadowUdpSocket},
    relay::{udprelay::ProxySocket, Address},
    transport::StreamConnection,
};

#[cfg(unix)]
use tokio::net::UnixStream;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    time,
};

use trust_dns_resolver::proto::{
    error::{ProtoError, ProtoErrorKind},
    op::Message,
};

use crate::{local::net::AutoProxyClientStream, net::MonProxySocket};

/// Collection of various DNS connections
#[allow(clippy::large_enum_variant)]
pub enum DnsClient {
    TcpLocal {
        stream: ShadowTcpStream,
    },
    UdpLocal {
        socket: UdpSocket,
    },
    #[cfg(unix)]
    #[allow(dead_code)]
    UnixStream {
        stream: UnixStream,
    },
    TcpRemote {
        stream: AutoProxyClientStream,
    },
    UdpRemote {
        socket: MonProxySocket,
        ns: Address,
    },
}

impl DnsClient {
    /// Connect to local provided TCP DNS server
    pub async fn connect_tcp_local(ns: SocketAddr, connect_opts: &ConnectOpts) -> io::Result<DnsClient> {
        let stream = ShadowTcpStream::connect_with_opts(&ns, connect_opts).await?;
        Ok(DnsClient::TcpLocal { stream })
    }

    /// Connect to local provided UDP DNS server
    pub async fn connect_udp_local(ns: SocketAddr, connect_opts: &ConnectOpts) -> io::Result<DnsClient> {
        let socket = ShadowUdpSocket::connect_with_opts(&ns, connect_opts).await?.into();
        Ok(DnsClient::UdpLocal { socket })
    }

    #[cfg(unix)]
    /// Connect to local provided Unix Domain Socket DNS server, in TCP-like protocol
    pub async fn connect_unix_stream<P: AsRef<Path>>(path: &P) -> io::Result<DnsClient> {
        let stream = UnixStream::connect(path).await?;
        Ok(DnsClient::UnixStream { stream })
    }

    /// Connect to remote DNS server through proxy in TCP
    pub async fn connect_tcp_remote(
        context: &SharedContext,
        svr_cfg: &ServerConfig,
        ns: &Address,
        connect_opts: &ConnectOpts,
        flow_stat: Arc<FlowStat>,
    ) -> io::Result<DnsClient> {
        let stream = AutoProxyClientStream::connect_proxied_no_score(
            context.clone(),
            connect_opts,
            svr_cfg,
            ns,
            Some(flow_stat),
            #[cfg(feature = "rate-limit")]
            None,
        )
        .await?;
        Ok(DnsClient::TcpRemote { stream })
    }

    /// Connect to remote DNS server through proxy in UDP
    pub async fn connect_udp_remote(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        ns: Address,
        connect_opts: &ConnectOpts,
        flow_stat: Arc<FlowStat>,
    ) -> io::Result<DnsClient> {
        match svr_cfg.protocol() {
            ServerProtocol::SS(ss_cfg) => {
                let socket = ProxySocket::connect_with_opts(context, svr_cfg, ss_cfg, connect_opts).await?;
                let socket = MonProxySocket::from_socket(socket, flow_stat);
                Ok(DnsClient::UdpRemote { socket, ns })
            }
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(_cfg) => {
                Err(io::Error::new(io::ErrorKind::Other, "not support dns udp over trojan"))
            }
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(_cfg) => Err(io::Error::new(io::ErrorKind::Other, "not support dns udp over vless")),
        }
    }

    /// Make a DNS lookup
    #[allow(dead_code)]
    pub async fn lookup(&mut self, mut msg: Message) -> Result<Message, ProtoError> {
        self.inner_lookup(&mut msg).await
    }

    /// Make a DNS lookup with timeout
    pub async fn lookup_timeout(&mut self, mut msg: Message, timeout: Duration) -> Result<Message, ProtoError> {
        match time::timeout(timeout, self.inner_lookup(&mut msg)).await {
            Ok(Ok(msg)) => Ok(msg),
            Ok(Err(error)) => Err(error),
            Err(..) => Err(ProtoErrorKind::Timeout.into()),
        }
    }

    async fn inner_lookup(&mut self, msg: &mut Message) -> Result<Message, ProtoError> {
        // Make a random ID
        msg.set_id(thread_rng().gen());

        trace!("DNS lookup {:?}", msg);

        match *self {
            DnsClient::TcpLocal { ref mut stream } => stream_query(stream, msg).await,
            DnsClient::UdpLocal { ref socket } => {
                let bytes = msg.to_vec()?;
                socket.send(&bytes).await?;

                let mut recv_buf = [0u8; 256];
                let n = socket.recv(&mut recv_buf).await?;

                Message::from_vec(&recv_buf[..n])
            }
            #[cfg(unix)]
            DnsClient::UnixStream { ref mut stream } => stream_query(stream, msg).await,
            DnsClient::TcpRemote { ref mut stream } => stream_query(stream, msg).await,
            DnsClient::UdpRemote { ref mut socket, ref ns } => {
                let bytes = msg.to_vec()?;
                socket.send(ns, &bytes).await?;

                let mut recv_buf = [0u8; 256];
                let (n, _) = socket.recv(&mut recv_buf).await?;

                Message::from_vec(&recv_buf[..n])
            }
        }
    }

    /// Check if the underlying connection is still connecting
    ///
    /// This will only work for TCP and UNIX Stream connections.
    /// UDP clients will always return `true`.
    pub async fn check_connected(&self) -> bool {
        match *self {
            DnsClient::TcpLocal { ref stream } => stream.check_connected(),
            DnsClient::UdpLocal { .. } => true,
            #[cfg(unix)]
            DnsClient::UnixStream { ref stream } => shadowsocks::net::check_peekable(stream),
            DnsClient::TcpRemote { ref stream } => stream.transport().check_connected(),
            DnsClient::UdpRemote { .. } => true,
        }
    }
}

pub async fn stream_query<S>(stream: &mut S, r: &Message) -> Result<Message, ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req_bytes = r.to_vec()?;

    // Prepend length
    let length = req_bytes.len();
    req_bytes.resize(length + 2, 0);
    req_bytes.copy_within(..length, 2);
    BigEndian::write_u16(&mut req_bytes[0..2], length as u16);

    stream.write_all(&req_bytes).await?;

    // Read response, [LENGTH][Message]
    let mut length_buf = [0u8; 2];
    stream.read_exact(&mut length_buf).await?;

    let length = BigEndian::read_u16(&length_buf);
    let mut rsp_bytes = BytesMut::with_capacity(length as usize);
    unsafe {
        rsp_bytes.advance_mut(length as usize);
    }
    stream.read_exact(&mut rsp_bytes).await?;

    Message::from_vec(&rsp_bytes)
}
