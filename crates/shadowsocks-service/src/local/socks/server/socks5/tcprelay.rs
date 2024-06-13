//! SOCKS5 TCP Server

use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
    str,
    sync::Arc,
};

use shadowsocks::{
    canceler::Canceler, config::Mode, relay::socks5::{
        self, Address, Command, Error as Socks5Error, HandshakeRequest, HandshakeResponse, PasswdAuthRequest,
        PasswdAuthResponse, Reply, TcpRequestHeader, TcpResponseHeader,
    }, transport::StreamConnection, ServerAddr
};
use tokio::net::TcpStream;
use tracing::{error, info_span, trace, warn, Instrument};

use crate::{
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::AutoProxyClientStream,
        socks::config::Socks5AuthConfig,
        utils::{establish_tcp_tunnel, establish_tcp_tunnel_bypassed},
    },
    net::utils::ignore_until_end,
};

pub struct Socks5TcpHandler {
    context: Arc<ServiceContext>,
    udp_bind_addr: Arc<ServerAddr>,
    balancer: PingBalancer,
    mode: Mode,
    auth: Arc<Socks5AuthConfig>,
}

impl Socks5TcpHandler {
    pub fn new(
        context: Arc<ServiceContext>,
        udp_bind_addr: Arc<ServerAddr>,
        balancer: PingBalancer,
        mode: Mode,
        auth: Arc<Socks5AuthConfig>,
    ) -> Socks5TcpHandler {
        Socks5TcpHandler {
            context,
            udp_bind_addr,
            balancer,
            mode,
            auth,
        }
    }

    async fn check_auth(&self, stream: &mut TcpStream, handshake_req: &HandshakeRequest) -> io::Result<()> {
        use std::io::Error;

        let allow_none = !self.auth.auth_required();

        for method in handshake_req.methods.iter() {
            match *method {
                socks5::SOCKS5_AUTH_METHOD_PASSWORD => {
                    let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_PASSWORD);
                    trace!("reply handshake {:?}", resp);
                    resp.write_to(stream).await?;

                    return self.check_auth_password(stream).await;
                }
                socks5::SOCKS5_AUTH_METHOD_NONE => {
                    if !allow_none {
                        trace!("none authentication method is not allowed");
                    } else {
                        let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
                        trace!("reply handshake {:?}", resp);
                        resp.write_to(stream).await?;

                        return Ok(());
                    }
                }
                _ => {
                    trace!("unsupported authentication method {}", method);
                }
            }
        }

        let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
        resp.write_to(stream).await?;

        trace!("reply handshake {:?}", resp);

        Err(Error::new(
            ErrorKind::Other,
            "currently shadowsocks-rust does not support authentication",
        ))
    }

    async fn check_auth_password(&self, stream: &mut TcpStream) -> io::Result<()> {
        use std::io::Error;

        const PASSWORD_AUTH_STATUS_FAILURE: u8 = 255;

        // Read initiation negociation

        let req = match PasswdAuthRequest::read_from(stream).await {
            Ok(i) => i,
            Err(err) => {
                let rsp = PasswdAuthResponse::new(err.as_reply().as_u8());
                let _ = rsp.write_to(stream).await;

                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Username/Password Authentication Initial request failed: {err}"),
                ));
            }
        };

        let user_name = match str::from_utf8(&req.uname) {
            Ok(u) => u,
            Err(..) => {
                let rsp = PasswdAuthResponse::new(PASSWORD_AUTH_STATUS_FAILURE);
                let _ = rsp.write_to(stream).await;

                return Err(Error::new(
                    ErrorKind::Other,
                    "Username/Password Authentication Initial request uname contains invaid characters",
                ));
            }
        };

        let password = match str::from_utf8(&req.passwd) {
            Ok(u) => u,
            Err(..) => {
                let rsp = PasswdAuthResponse::new(PASSWORD_AUTH_STATUS_FAILURE);
                let _ = rsp.write_to(stream).await;

                return Err(Error::new(
                    ErrorKind::Other,
                    "Username/Password Authentication Initial request passwd contains invaid characters",
                ));
            }
        };

        if self.auth.passwd.check_user(user_name, password) {
            trace!(
                "socks5 authenticated with Username/Password method, user: {}, password: {}",
                user_name,
                password
            );

            let rsp = PasswdAuthResponse::new(0);
            rsp.write_to(stream).await?;

            Ok(())
        } else {
            let rsp = PasswdAuthResponse::new(PASSWORD_AUTH_STATUS_FAILURE);
            rsp.write_to(stream).await?;

            error!(
                "socks5 rejected Username/Password user: {}, password: {}",
                user_name, password
            );

            Err(Error::new(
                ErrorKind::Other,
                format!("Username/Password Authentication failed, user: {user_name}, password: {password}"),
            ))
        }
    }

    pub async fn handle_socks5_client(self, mut stream: TcpStream, peer_addr: SocketAddr, canceler: &Canceler) -> io::Result<()> {
        // 1. Handshake

        let handshake_req = match HandshakeRequest::read_from(&mut stream).await {
            Ok(r) => r,
            Err(Socks5Error::IoError(ref err)) if err.kind() == ErrorKind::UnexpectedEof => {
                trace!("socks5 handshake early eof");
                return Ok(());
            }
            Err(err) => {
                error!(error = ?err, "socks5 handshake error");
                return Err(err.into());
            }
        };

        trace!("socks5 {:?}", handshake_req);
        self.check_auth(&mut stream, &handshake_req).await?;

        // 2. Fetch headers
        let header = match TcpRequestHeader::read_from(&mut stream).await {
            Ok(h) => h,
            Err(err) => {
                error!(error = ?err, "failed to get TcpRequestHeader");
                let rh = TcpResponseHeader::new(err.as_reply(), Address::SocketAddress(peer_addr));
                rh.write_to(&mut stream).await?;
                return Err(err.into());
            }
        };

        trace!("socks5 {:?}", header);

        let addr = header.address;

        // 3. Handle Command
        match header.command {
            Command::TcpConnect => {
                let span = info_span!("tcp", target = addr.to_string());
                self.handle_tcp_connect(stream, peer_addr, addr, canceler).instrument(span).await
            }
            Command::UdpAssociate => self.handle_udp_associate(stream, addr).await,
            Command::TcpBind => {
                warn!("BIND is not supported");
                let rh = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr);
                rh.write_to(&mut stream).await?;

                Ok(())
            }
        }
    }

    async fn handle_tcp_connect(
        self,
        #[allow(unused_mut)] mut stream: TcpStream,
        peer_addr: SocketAddr,
        target_addr: Address,
        canceler: &Canceler,
    ) -> io::Result<()> {
        if !self.mode.enable_tcp() {
            warn!("TCP CONNECT is disabled");

            let rh = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, target_addr);
            rh.write_to(&mut stream).await?;

            return Ok(());
        }

        let (remote_result, server_opt, span) = {
            if self.balancer.is_empty() {
                let span = info_span!("bypass");
                (
                    AutoProxyClientStream::connect_bypassed(self.context.as_ref(), &target_addr, canceler)
                        .instrument(span.clone())
                        .await,
                    None,
                    span,
                )
            } else {
                let server = self.balancer.best_tcp_server();

                let span = info_span!(
                    "miner",
                    addr = server.server_config().addr().to_string(),
                    score = server.tcp_score().score()
                );

                (
                    AutoProxyClientStream::connect_with_opts(&self.context, &server, &target_addr, server.connect_opts_ref(), canceler)
                        .instrument(span.clone())
                        .await,
                    Some(server),
                    span,
                )
            }
        };

        async move {
            let mut remote = match remote_result {
                Ok(remote) => {
                    // Tell the client that we are ready
                    let header =
                        TcpResponseHeader::new(socks5::Reply::Succeeded, Address::SocketAddress(remote.local_addr()?));
                    header.write_to(&mut stream).await?;

                    trace!("sent header: {:?}", header);

                    remote
                }
                Err(err) => {
                    let reply = match err.kind() {
                        ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                        ErrorKind::ConnectionAborted => Reply::HostUnreachable,
                        _ => Reply::NetworkUnreachable,
                    };

                    let dummy_address = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
                    let header = TcpResponseHeader::new(reply, Address::SocketAddress(dummy_address));
                    header.write_to(&mut stream).await?;

                    return Err(err);
                }
            };

            match server_opt {
                Some(server) => {
                    #[cfg(feature = "rate-limit")]
                    let stream = shadowsocks::transport::RateLimitedStream::from_stream(
                        stream,
                        Some(self.context.rate_limiter()),
                    );

                    let svr_cfg = server.server_config();
                    establish_tcp_tunnel(
                        self.context.as_ref(),
                        svr_cfg,
                        stream,
                        &mut remote,
                        peer_addr,
                        &target_addr,
                    )
                    .await
                }
                None => establish_tcp_tunnel_bypassed(&mut stream, &mut remote, peer_addr, &target_addr, None).await,
            }
        }
        .instrument(span)
        .await
    }

    async fn handle_udp_associate(self, mut stream: TcpStream, client_addr: Address) -> io::Result<()> {
        if !self.mode.enable_udp() {
            warn!("socks5 udp is disabled");

            let rh = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, client_addr);
            rh.write_to(&mut stream).await?;

            return Ok(());
        }

        // shadowsocks accepts both TCP and UDP from the same address

        let rh = TcpResponseHeader::new(socks5::Reply::Succeeded, self.udp_bind_addr.as_ref().into());
        rh.write_to(&mut stream).await?;

        // Hold connection until EOF.
        let _ = ignore_until_end(&mut stream).await;

        Ok(())
    }
}
