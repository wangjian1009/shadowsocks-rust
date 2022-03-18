//! Shadowsocks TCP server

use std::{
    future::Future,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use log::{debug, error, info, trace, warn};
use shadowsocks::{
    config::ServerProtocol,
    crypto::v1::CipherKind,
    net::{AcceptOpts, Destination},
    relay::{
        socks5::{Address, Error as Socks5Error},
        tcprelay::{utils::copy_encrypted_bidirectional, ProxyServerStream},
    },
    timeout::Sleep,
    transport::{
        direct::{TcpAcceptor, TcpConnector},
        Acceptor, Connection, Connector, StreamConnection,
    },
    ServerAddr, ServerConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
    time,
};

use crate::net::{utils::ignore_until_end, MonProxyStream};

use super::{connection::ConnectionInfo, context::ServiceContext};

#[cfg(feature = "rate-limit")]
use shadowsocks::transport::RateLimiter;

#[cfg(feature = "transport")]
use shadowsocks::config::TransportAcceptorConfig;

#[cfg(feature = "transport-ws")]
use shadowsocks::transport::websocket::WebSocketAcceptor;

#[cfg(feature = "transport-tls")]
use shadowsocks::transport::tls::TlsAcceptor;

#[cfg(feature = "transport-mkcp")]
use shadowsocks::net::UdpSocket;
#[cfg(feature = "transport-mkcp")]
use shadowsocks::transport::mkcp::MkcpAcceptor;

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "server-mock")] {
        use super::context::ServerMockProtocol;
        use super::dns::run_dns_tcp_stream;
    }
    else {
    }
}

cfg_if! {
    if #[cfg(feature = "vless")] {
        use shadowsocks::{vless::InboundHandler};
    }
}

pub struct TcpServer {
    context: Arc<ServiceContext>,
    connector: Arc<TcpConnector>,
    accept_opts: AcceptOpts,
}

impl TcpServer {
    pub fn new(context: Arc<ServiceContext>, connector: Arc<TcpConnector>, accept_opts: AcceptOpts) -> TcpServer {
        TcpServer {
            context,
            connector,
            accept_opts,
        }
    }

    pub async fn run(self, svr_cfg: &ServerConfig) -> io::Result<()> {
        #[cfg(feature = "transport")]
        match svr_cfg.acceptor_transport().as_ref() {
            Some(ref transport) => match transport {
                #[cfg(feature = "transport-ws")]
                &TransportAcceptorConfig::Ws(ws_config) => {
                    let listener = TcpAcceptor::bind_server_with_opts(
                        self.context.context().as_ref(),
                        svr_cfg.external_addr(),
                        self.accept_opts.clone(),
                    )
                    .await?;
                    let listener = WebSocketAcceptor::new(ws_config, listener);
                    self.run_with_acceptor(listener, svr_cfg).await
                }
                #[cfg(feature = "transport-tls")]
                &TransportAcceptorConfig::Tls(tls_config) => {
                    let listener = TcpAcceptor::bind_server_with_opts(
                        self.context.context().as_ref(),
                        svr_cfg.external_addr(),
                        self.accept_opts.clone(),
                    )
                    .await?;
                    let listener = TlsAcceptor::new(tls_config, listener).await?;
                    self.run_with_acceptor(listener, svr_cfg).await
                }
                #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
                &TransportAcceptorConfig::Wss(ws_config, tls_config) => {
                    let listener = TcpAcceptor::bind_server_with_opts(
                        self.context.context().as_ref(),
                        svr_cfg.external_addr(),
                        self.accept_opts.clone(),
                    )
                    .await?;
                    let listener = TlsAcceptor::new(tls_config, listener).await?;
                    let listener = WebSocketAcceptor::new(ws_config, listener);
                    self.run_with_acceptor(listener, svr_cfg).await
                }
                #[cfg(feature = "transport-mkcp")]
                &TransportAcceptorConfig::Mkcp(mkcp_config) => {
                    let socket = UdpSocket::listen_server_with_opts(
                        self.context.context().as_ref(),
                        svr_cfg.external_addr(),
                        self.accept_opts.clone(),
                    )
                    .await?;
                    let r = Arc::new(socket);
                    let w = r.clone();
                    let local_addr = r.local_addr()?;
                    let listener = MkcpAcceptor::new(Arc::new(mkcp_config.clone()), local_addr, r, w, None);
                    self.run_with_acceptor(listener, svr_cfg).await
                }
            },
            None => {
                let listener = TcpAcceptor::bind_server_with_opts(
                    self.context.context().as_ref(),
                    svr_cfg.external_addr(),
                    self.accept_opts.clone(),
                )
                .await?;
                self.run_with_acceptor(listener, svr_cfg).await
            }
        }

        #[cfg(not(feature = "transport"))]
        {
            let listener = TcpAcceptor::bind_server_with_opts(
                self.context.context().as_ref(),
                svr_cfg.external_addr(),
                self.accept_opts.clone(),
            )
            .await?;

            self.run_with_acceptor(listener, svr_cfg).await
        }
    }

    async fn run_with_acceptor<A: Acceptor>(self, listener: A, svr_cfg: &ServerConfig) -> io::Result<()> {
        info!(
            "{} tcp server listening on {}{}, inbound address {}",
            svr_cfg.protocol().name(),
            listener.local_addr().expect("listener.local_addr"),
            svr_cfg.acceptor_transport_tag(),
            svr_cfg.addr(),
        );

        cfg_if! {
            if #[cfg(feature = "vless")] {
                let mut vless_inbound = None;

                if let ServerProtocol::Vless(cfg) = svr_cfg.protocol() {
                    vless_inbound = Some(Arc::new(InboundHandler::new(cfg)?));
                }
            }
        }

        loop {
            let flow_stat = self.context.flow_stat();
            let connection_stat = self.context.connection_stat();
            #[cfg(feature = "rate-limit")]
            let connection_bound_width = self.context.connection_bound_width();

            let mut idle_timeout = None;

            #[cfg(feature = "rate-limit")]
            let mut rate_limiter = None;

            let (local_stream, peer_addr) = match listener.accept().await.map(|(s, addr)| {
                #[allow(unused_mut)]
                let mut s = match s {
                    Connection::Stream(s) => s,
                    Connection::Packet { .. } => unreachable!(),
                };

                let addr = match addr.unwrap() {
                    ServerAddr::SocketAddr(addr) => addr,
                    ServerAddr::DomainName(..) => unreachable!(),
                };

                if let Some(cfg_idle_timeout) = svr_cfg.idle_timeout() {
                    idle_timeout = Some(Arc::new(Mutex::new(Sleep::new(cfg_idle_timeout))));
                }

                #[cfg(feature = "rate-limit")]
                if let Some(connection_bound_width) = connection_bound_width {
                    let quota = connection_bound_width.to_quota_byte_per_second().unwrap();
                    rate_limiter = Some(Arc::new(RateLimiter::new(quota)));
                }

                #[cfg(feature = "rate-limit")]
                s.set_rate_limit(rate_limiter.clone());

                (
                    MonProxyStream::from_stream(
                        s,
                        flow_stat,
                        match &idle_timeout {
                            Some(ref idle_timeout) => Some(idle_timeout.clone()),
                            None => None,
                        },
                    ),
                    addr,
                )
            }) {
                Ok(s) => s,
                Err(err) => {
                    error!("tcp server accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            #[cfg(not(feature = "server-limit"))]
            let conn = connection_stat.add_in_connection(peer_addr).await;

            #[cfg(feature = "server-limit")]
            let (conn, in_count_guard) = match connection_stat
                .check_add_in_connection(peer_addr, self.context.limit_connection_per_ip())
                .await
            {
                Ok(r) => r,
                Err(_err) => {
                    match self.context.limit_connection_close_delay() {
                        None => error!(
                            "tcp server: from {} limit {} reached, close immediately",
                            peer_addr.ip(),
                            self.context.limit_connection_per_ip().unwrap(),
                        ),
                        Some(delay) => {
                            error!(
                                "tcp server: from {} limit {} reached, close delay {:?}",
                                peer_addr.ip(),
                                self.context.limit_connection_per_ip().unwrap(),
                                delay
                            );
                            let delay = *delay;
                            tokio::spawn(async move {
                                let _local_stream = local_stream;
                                tokio::time::sleep(delay).await;
                            });
                        }
                    }
                    continue;
                }
            };

            let client = TcpServerClient {
                context: self.context.clone(),
                connector: self.connector.clone(),
                conn,
                peer_addr,
                timeout: svr_cfg.timeout(),
                request_recv_timeout: svr_cfg.request_recv_timeout().clone(),
                idle_timeout,
                #[cfg(feature = "rate-limit")]
                rate_limiter,
            };

            let connection_stat = connection_stat.clone();
            let conn_id = client.conn.id;

            match svr_cfg.protocol() {
                ServerProtocol::SS(ss_cfg) => {
                    let local_stream = ProxyServerStream::from_stream(
                        self.context.context(),
                        local_stream,
                        ss_cfg.method(),
                        ss_cfg.key(),
                    );
                    let method = ss_cfg.method();
                    tokio::spawn(async move {
                        if let Err(err) = client.serve(method, local_stream).await {
                            debug!("tcp server stream aborted with error: {}", err);
                        }

                        #[cfg(feature = "server-limit")]
                        connection_stat.remove_in_connection(&conn_id, in_count_guard).await;

                        #[cfg(not(feature = "server-limit"))]
                        connection_stat.remove_in_connection(&conn_id).await;
                    });
                }
                #[cfg(feature = "trojan")]
                ServerProtocol::Trojan(cfg) => {
                    let hash = cfg.hash().clone();
                    tokio::spawn(async move {
                        if let Err(err) = client.serve_trojan(&hash, local_stream).await {
                            debug!("tcp server stream aborted with error: {}", err);
                        }

                        #[cfg(feature = "server-limit")]
                        connection_stat.remove_in_connection(&conn_id, in_count_guard).await;

                        #[cfg(not(feature = "server-limit"))]
                        connection_stat.remove_in_connection(&conn_id).await;
                    });
                }
                #[cfg(feature = "vless")]
                ServerProtocol::Vless(..) => {
                    let inbound = vless_inbound.clone();
                    tokio::spawn(async move {
                        if let Err(err) = client.serve_vless(inbound.unwrap(), local_stream).await {
                            debug!("tcp server stream aborted with error: {}", err);
                        }

                        #[cfg(feature = "server-limit")]
                        connection_stat.remove_in_connection(&conn_id, in_count_guard).await;

                        #[cfg(not(feature = "server-limit"))]
                        connection_stat.remove_in_connection(&conn_id).await;
                    });
                }
            }
        }
    }
}

#[inline]
async fn timeout_fut<F, R>(duration: Option<Duration>, f: F) -> io::Result<R>
where
    F: Future<Output = io::Result<R>>,
{
    match duration {
        None => f.await,
        Some(d) => match time::timeout(d, f).await {
            Ok(o) => o,
            Err(..) => Err(ErrorKind::TimedOut.into()),
        },
    }
}

struct TcpServerClient {
    context: Arc<ServiceContext>,
    connector: Arc<TcpConnector>,
    conn: Arc<ConnectionInfo>,
    peer_addr: SocketAddr,
    timeout: Option<Duration>,
    request_recv_timeout: Option<Duration>,
    idle_timeout: Option<Arc<Mutex<Sleep>>>,
    #[cfg(feature = "rate-limit")]
    rate_limiter: Option<Arc<RateLimiter>>,
}

impl TcpServerClient {
    async fn serve<IS>(self, method: CipherKind, mut stream: ProxyServerStream<MonProxyStream<IS>>) -> io::Result<()>
    where
        IS: StreamConnection,
    {
        let connection_stat = self.context.connection_stat();

        let mut request_timeout = None;
        if let Some(base_timeout) = self.request_recv_timeout {
            request_timeout = Some(base_timeout + Duration::from_secs(rand::random::<u64>() % base_timeout.as_secs()));
        }

        let target_addr = match match request_timeout {
            None => Address::read_from(&mut stream).await,
            Some(d) => match time::timeout(d, Address::read_from(&mut stream)).await {
                Ok(r) => r,
                Err(..) => Err(Socks5Error::IoError(ErrorKind::TimedOut.into())),
            },
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
                    "handshake failed, maybe wrong method or key, or under replay attacks. peer: {}, error: {}",
                    self.peer_addr, err
                );

                // Unwrap and get the plain stream.
                // Otherwise it will keep reporting decryption error before reaching EOF.
                //
                // Note: This will drop all data in the decryption buffer, which is no going back.
                let mut stream = stream.into_inner();

                let res = ignore_until_end(&mut stream).await;

                trace!(
                    "silent-drop peer: {} is now closing with result {:?}",
                    self.peer_addr,
                    res
                );

                return Ok(());
            }
        };
        // self.conn.lock().await.remote_addr

        trace!(
            "accepted tcp client connection {}, establishing tunnel to {}",
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

        if self.context.check_client_blocked(&self.peer_addr) {
            warn!("access denied from {} by ACL rules", self.peer_addr);
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
                    "tcp tunnel {} -> {} connect failed, error: {}",
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
                        "tcp tunnel {} -> {} sent TFO connect without data",
                        self.peer_addr,
                        target_addr
                    );
                }
            }
        }

        debug!(
            "established tcp tunnel {} <-> {} with {:?}",
            self.peer_addr,
            target_addr,
            self.context.connect_opts_ref()
        );

        match copy_encrypted_bidirectional(method, &mut stream, &mut remote_stream, &self.idle_timeout).await {
            Ok((rn, wn)) => {
                trace!(
                    "tcp tunnel {} <-> {} closed, L2R {} bytes, R2L {} bytes",
                    self.peer_addr,
                    target_addr,
                    rn,
                    wn
                );
            }
            Err(err) => {
                trace!(
                    "tcp tunnel {} <-> {} closed with error: {}",
                    self.peer_addr,
                    target_addr,
                    err
                );
            }
        }

        Ok(())
    }
}

#[cfg(feature = "trojan")]
mod trojan;

#[cfg(feature = "vless")]
mod vless;
