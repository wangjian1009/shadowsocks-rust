//! DNS Relay Upstream

#[cfg(unix)]
use std::path::Path;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use hickory_resolver::proto::{
    error::{ProtoError, ProtoErrorKind},
    op::Message,
};
use tracing::{error, trace};
use lru_time_cache::{Entry, LruCache};
use rand::{thread_rng, Rng};
use shadowsocks::{
    canceler::Canceler,
    config::ServerProtocol,
    context::SharedContext,
    net::{ConnectOpts, FlowStat, TcpStream as ShadowTcpStream, UdpSocket as ShadowUdpSocket},
    relay::{udprelay::{options::UdpSocketControlData, ProxySocket}, Address},
    transport::StreamConnection,
    ServerAddr,
};

#[cfg(unix)]
use tokio::net::UnixStream;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    time,
};

use crate::{
    local::{context::ServiceContext, loadbalancing::ServerIdent, net::{udp::generate_client_session_id, AutoProxyClientStream}},
    net::{packet_window::PacketWindowFilter, MonProxySocket},
    DEFAULT_UDP_EXPIRY_DURATION,
};

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
        control: UdpSocketControlData,
        server_windows: LruCache<u64, PacketWindowFilter>,
    },
}

impl DnsClient {
    /// Connect to local provided TCP DNS server
    pub async fn connect_tcp_local(
        ns: SocketAddr,
        connect_opts: &ConnectOpts,
        canceler: &Canceler,
    ) -> io::Result<DnsClient> {
        let mut waiter = canceler.waiter();
        tokio::select! {
            r = ShadowTcpStream::connect_with_opts(&ns, connect_opts) => {
                let stream = r?;
                Ok(DnsClient::TcpLocal { stream })
            }
            _ = waiter.wait() => {
                tracing::info!("connect_tcp_local canceled");
                Err(io::Error::new(io::ErrorKind::Other, "canceled"))
            }
        }
    }

    /// Connect to local provided UDP DNS server
    pub async fn connect_udp_local(
        ns: SocketAddr,
        connect_opts: &ConnectOpts,
        canceler: &Canceler,
    ) -> io::Result<DnsClient> {
        let mut waiter = canceler.waiter();
        tokio::select! {
            r = ShadowUdpSocket::connect_with_opts(&ns, connect_opts) => {
                let socket = r?.into();
                Ok(DnsClient::UdpLocal { socket })
            }
            _ = waiter.wait() => {
                tracing::info!("connect_tcp_local canceled");
                Err(io::Error::new(io::ErrorKind::Other, "canceled"))
            }
        }
    }

    #[cfg(unix)]
    /// Connect to local provided Unix Domain Socket DNS server, in TCP-like protocol
    pub async fn connect_unix_stream<P: AsRef<Path>>(path: &P, canceler: &Canceler) -> io::Result<DnsClient> {
        let mut waiter = canceler.waiter();
        tokio::select! {
            r = UnixStream::connect(path) => {
                let stream = r?;
                Ok(DnsClient::UnixStream { stream })
            }
            _ = waiter.wait() => {
                tracing::info!("connect_unix_stream canceled");
                Err(io::Error::new(io::ErrorKind::Other, "canceled"))
            }
        }
    }

    /// Connect to remote DNS server through proxy in TCP
    pub async fn connect_tcp_remote(
        context: &ServiceContext,
        svr: &ServerIdent,
        ns: &Address,
        canceler: &Canceler,
    ) -> io::Result<DnsClient> {
        let stream = AutoProxyClientStream::connect_proxied(context, svr, ns, canceler).await?;
        Ok(DnsClient::TcpRemote { stream })
    }

    /// Connect to remote DNS server through proxy in UDP
    pub async fn connect_udp_remote(
        context: SharedContext,
        svr: &ServerIdent,
        ns: Address,
        connect_opts: &ConnectOpts,
        flow_stat: Arc<FlowStat>,
        canceler: &Canceler,
    ) -> io::Result<DnsClient> {
        let svr_cfg = svr.server_config();
        match svr_cfg.protocol() {
            ServerProtocol::SS(ss_cfg) => {
                let socket = ProxySocket::connect_with_opts(context.clone(), svr_cfg, ss_cfg, connect_opts, canceler).await?;
                let socket = MonProxySocket::from_socket(socket, flow_stat.clone());
                let mut control = UdpSocketControlData::default();
                control.client_session_id = generate_client_session_id();
                control.packet_id = 0; // AEAD-2022 Packet ID starts from 1
                Ok(DnsClient::UdpRemote {
                    socket,
                    ns,
                    control,
                    // NOTE: expiry duration should be configurable. But the Client is held by DnsClientCache, which expires very quickly.
                    server_windows: LruCache::with_expiry_duration(DEFAULT_UDP_EXPIRY_DURATION),
                })
            }
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(_cfg) => {
                Err(io::Error::new(io::ErrorKind::Other, "not support dns udp over trojan"))
            }
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(_cfg) => Err(io::Error::new(io::ErrorKind::Other, "not support dns udp over vless")),
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(_cfg) => Err(io::Error::new(io::ErrorKind::Other, "not support dns udp over tuic")),
            #[cfg(feature = "wireguard")]
            ServerProtocol::WG(_cfg) => Err(io::Error::new(
                io::ErrorKind::Other,
                "not support dns udp over wireguard",
            )),
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
            DnsClient::UdpRemote {
                ref mut socket,
                ref ns,
                ref mut control,
                ref mut server_windows,
            } => {
                control.packet_id = match control.packet_id.checked_add(1) {
                    Some(i) => i,
                    None => return Err(ProtoErrorKind::Message("packet id overflows").into()),
                };

                let bytes = msg.to_vec()?;
                socket.send_with_ctrl(&ServerAddr::from(ns), control, &bytes).await?;

                let mut recv_buf = [0u8; 256];
                let (n, _, recv_control) = socket.recv_with_ctrl(&mut recv_buf).await?;

                if let Some(server_control) = recv_control {
                    let filter = match server_windows.entry(server_control.server_session_id) {
                        Entry::Occupied(occ) => occ.into_mut(),
                        Entry::Vacant(vac) => vac.insert(PacketWindowFilter::new()),
                    };

                    if !filter.validate_packet_id(server_control.packet_id, u64::MAX) {
                        error!(
                            "dns client for {} packet_id {} out of window",
                            ns, server_control.packet_id
                        );

                        return Err(ProtoErrorKind::Message("packet id out of window").into());
                    }
                }

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
            DnsClient::TcpRemote { ref stream } => stream.check_connected(),
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
