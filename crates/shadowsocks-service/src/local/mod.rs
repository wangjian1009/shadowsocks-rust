//! Shadowsocks Local Server

use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    sync::Arc,
    task,
    time::Duration,
};

use futures::{future, ready};
use shadowsocks::{
    canceler::CancelWaiter,
    config::{Mode, ServerProtocol, ServerType},
    context::Context,
    net::{AcceptOpts, ConnectOpts},
    relay::socks5::Address,
    ServerAddr,
};
use tokio::task::JoinHandle;
use tracing::{info_span, trace, Instrument};

use crate::{
    config::{Config, ConfigType, ProtocolType},
    dns::build_dns_resolver,
};

#[cfg(feature = "local-maintain")]
mod maintain;

mod start_stat;
use start_stat::StartStat;

/// 解析证书等可以脱离Android运行，环境相关在模块内区分
pub mod android;

use self::{
    context::ServiceContext,
    loadbalancing::{PingBalancer, PingBalancerBuilder},
};

#[cfg(feature = "local-dns")]
use self::dns::{Dns, DnsBuilder};
#[cfg(feature = "local-http")]
use self::http::{Http, HttpBuilder};
#[cfg(feature = "local-redir")]
use self::redir::{Redir, RedirBuilder};
use self::socks::{Socks, SocksBuilder};
#[cfg(feature = "local-tun")]
use self::tun::{Tun, TunBuilder};
#[cfg(feature = "local-tunnel")]
use self::tunnel::{Tunnel, TunnelBuilder};

#[cfg(feature = "local-api")]
pub mod api;

pub mod context;
#[cfg(feature = "local-dns")]
pub mod dns;
#[cfg(any(feature = "local-http", feature = "local-api"))]
pub mod http;
pub mod loadbalancing;
pub mod net;
#[cfg(feature = "local-redir")]
pub mod redir;
pub mod socks;
#[cfg(feature = "local-tun")]
pub mod tun;
#[cfg(feature = "local-tunnel")]
pub mod tunnel;
pub mod utils;
#[cfg(feature = "wireguard")]
mod wg;

#[cfg(feature = "local-flow-stat")]
mod reporter;

#[cfg(feature = "local-flow-stat")]
use crate::config::LocalFlowStatAddress;

#[cfg(any(feature = "local-tun", feature = "wireguard"))]
mod tun_sys;

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "sniffer")] {
        use crate::sniffer::SnifferProtocol;
        use crate::local::context::ProtocolAction;
    }
}

/// Default TCP Keep Alive timeout
///
/// This is borrowed from Go's `net` library's default setting
pub(crate) const LOCAL_DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);

struct ServerHandle(JoinHandle<io::Result<()>>);

impl Drop for ServerHandle {
    #[inline]
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Future for ServerHandle {
    type Output = io::Result<()>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match ready!(Pin::new(&mut self.0).poll(cx)) {
            Ok(res) => res.into(),
            Err(err) => Err(io::Error::new(ErrorKind::Other, err)).into(),
        }
    }
}

/// Local Server instance
pub struct Server {
    balancer: PingBalancer,
    socks_servers: Vec<Socks>,
    #[cfg(feature = "local-tunnel")]
    tunnel_servers: Vec<Tunnel>,
    #[cfg(feature = "local-http")]
    http_servers: Vec<Http>,
    #[cfg(feature = "local-tun")]
    tun_servers: Vec<Tun>,
    #[cfg(feature = "local-dns")]
    dns_servers: Vec<Dns>,
    #[cfg(feature = "local-redir")]
    redir_servers: Vec<Redir>,
    #[cfg(feature = "wireguard")]
    wg_server: Option<wg::Server>,
    #[cfg(feature = "local-maintain")]
    maintain_server: Option<maintain::MaintainServer>,
    #[cfg(feature = "local-flow-stat")]
    reporter_server: Option<reporter::ReporterServer>,
}

impl Server {
    /// Create a shadowsocks local server
    pub async fn new(context: Arc<Context>, cancel_waiter: CancelWaiter, config: Config) -> io::Result<Server> {
        assert!(config.config_type == ConfigType::Local && !config.local.is_empty());

        trace!("{:?}", config);

        // Warning for Stream Ciphers
        #[cfg(feature = "stream-cipher")]
        for inst in config.server.iter() {
            let server = &inst.config;

            if let ServerProtocol::SS(ss_config) = server.protocol() {
                if ss_config.method().is_stream() {
                    tracing::warn!("stream cipher {} for server {} have inherent weaknesses (see discussion in https://github.com/shadowsocks/shadowsocks-org/issues/36). \
                    DO NOT USE. It will be removed in the future.", ss_config.method(), server.addr());
                }
            }
        }

        #[cfg(all(unix, not(target_os = "android")))]
        if let Some(nofile) = config.nofile {
            use crate::sys::set_nofile;
            if let Err(err) = set_nofile(nofile) {
                tracing::warn!("set_nofile {} failed, error: {}", nofile, err);
            }
        }

        // Global ServiceContext template
        // Each Local instance will hold a copy of its fields
        let mut context = ServiceContext::new(context, cancel_waiter.clone());

        let mut connect_opts = ConnectOpts {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            fwmark: config.outbound_fwmark,

            #[cfg(target_os = "android")]
            vpn_protect_path: config.outbound_vpn_protect_path,

            bind_interface: config.outbound_bind_interface,
            bind_local_addr: config.outbound_bind_addr,

            ..Default::default()
        };
        connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
        connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
        connect_opts.tcp.nodelay = config.no_delay;
        connect_opts.tcp.fastopen = config.fast_open;
        connect_opts.tcp.keepalive = config.keep_alive.or(Some(LOCAL_DEFAULT_KEEPALIVE_TIMEOUT));
        connect_opts.tcp.mptcp = config.mptcp;
        context.set_connect_opts(connect_opts);

        let mut accept_opts = AcceptOpts {
            ipv6_only: config.ipv6_only,
            ..Default::default()
        };
        accept_opts.tcp.send_buffer_size = config.inbound_send_buffer_size;
        accept_opts.tcp.recv_buffer_size = config.inbound_recv_buffer_size;
        accept_opts.tcp.nodelay = config.no_delay;
        accept_opts.tcp.fastopen = config.fast_open;
        accept_opts.tcp.keepalive = config.keep_alive.or(Some(LOCAL_DEFAULT_KEEPALIVE_TIMEOUT));
        accept_opts.tcp.mptcp = config.mptcp;
        context.set_accept_opts(accept_opts);

        if let Some(resolver) = build_dns_resolver(
            config.dns,
            config.ipv6_first,
            config.dns_cache_size,
            context.connect_opts_ref(),
        )
        .await
        {
            context.set_dns_resolver(Arc::new(resolver));
        }

        if config.ipv6_first {
            context.set_ipv6_first(config.ipv6_first);
        }

        if let Some(acl) = config.acl {
            context.set_acl(Arc::new(acl));
        }

        context.set_security_config(&config.security);

        #[cfg(feature = "rate-limit")]
        if let Some(bound_width) = config.rate_limit.as_ref() {
            tracing::info!("bound-width={}", bound_width);
            context.rate_limiter().set_rate_limit(Some(bound_width.clone()))?;
        }

        #[cfg(feature = "sniffer-bittorrent")]
        if let Some(reject_bittorrent) = config.reject_bittorrent {
            tracing::info!("reject bittorrent = {}", reject_bittorrent);
            if reject_bittorrent {
                context.set_protocol_action(SnifferProtocol::Bittorrent, Some(ProtocolAction::Reject));
                context.set_protocol_action(SnifferProtocol::Utp, Some(ProtocolAction::Reject));
            }
        }

        // vfut.push(async {
        //     tokio::time::sleep(Duration::from_secs(10)).await;
        //     tracing::error!("xxxxxxxxx: test done!");
        //     unsafe { *(0 as *mut u32) = 42; }
        //     Ok(())
        // }.boxed());
        // let (res, ..) = future::select_all(vfut).await;
        // let (res, _) = vfut.into_future().await;
        // res.unwrap()

        assert!(!config.local.is_empty(), "no valid local server configuration");

        // Create a service balancer for choosing between multiple servers
        let balancer = {
            let mut mode: Option<Mode> = None;

            for local in &config.local {
                mode = Some(match mode {
                    None => local.config.mode,
                    Some(m) => m.merge(local.config.mode),
                });
            }

            let mode = mode.unwrap_or(Mode::TcpOnly);

            // Load balancer will hold an individual ServiceContext
            let mut balancer_builder = PingBalancerBuilder::new(Arc::new(context.clone()), mode);

            // max_server_rtt have to be set before add_server
            if let Some(rtt) = config.balancer.max_server_rtt {
                balancer_builder.max_server_rtt(rtt);
            }

            if let Some(intv) = config.balancer.check_interval {
                balancer_builder.check_interval(intv);
            }

            if let Some(intv) = config.balancer.check_best_interval {
                balancer_builder.check_best_interval(intv);
            }

            for server in &config.server {
                if let Err(err) = balancer_builder.add_server(server.config.clone()) {
                    tracing::warn!(err = ?err, "add server failed");
                }
            }

            balancer_builder.build().await?
        };

        let mut local_server = Server {
            balancer: balancer.clone(),
            socks_servers: Vec::new(),
            #[cfg(feature = "local-tunnel")]
            tunnel_servers: Vec::new(),
            #[cfg(feature = "local-http")]
            http_servers: Vec::new(),
            #[cfg(feature = "local-tun")]
            tun_servers: Vec::new(),
            #[cfg(feature = "local-dns")]
            dns_servers: Vec::new(),
            #[cfg(feature = "local-redir")]
            redir_servers: Vec::new(),
            #[cfg(feature = "wireguard")]
            wg_server: None,
            #[cfg(feature = "local-maintain")]
            maintain_server: None,
            #[cfg(feature = "local-flow-stat")]
            reporter_server: None,
        };

        for local_instance in config.local {
            let local_config = local_instance.config;

            // Clone from global ServiceContext instance
            // It will shares Shadowsocks' global context, and FlowStat, DNS reverse cache
            let mut context = context.clone();

            // Private ACL
            if let Some(acl) = local_instance.acl {
                context.set_acl(Arc::new(acl))
            }

            let balancer = balancer.clone();

            match local_config.protocol {
                ProtocolType::Socks => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::new(ErrorKind::Other, "socks requires local address")),
                    };

                    let mut server_builder = SocksBuilder::with_context(Arc::new(context), client_addr, balancer);
                    server_builder.set_mode(local_config.mode);
                    server_builder.set_socks5_auth(local_config.socks5_auth);

                    if let Some(c) = config.udp_max_associations {
                        server_builder.set_udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        server_builder.set_udp_expiry_duration(d);
                    }
                    if let Some(b) = local_config.udp_addr {
                        server_builder.set_udp_bind_addr(b.clone());
                    }

                    let server = server_builder.build().await?;
                    local_server.socks_servers.push(server);
                }
                #[cfg(feature = "local-tunnel")]
                ProtocolType::Tunnel => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::new(ErrorKind::Other, "tunnel requires local address")),
                    };

                    let forward_addr = match local_config.forward_addr.expect("tunnel requires forward address") {
                        ServerAddr::SocketAddr(addr) => Address::SocketAddress(addr),
                        ServerAddr::DomainName(path, port) => Address::DomainNameAddress(path, port),
                    };

                    let mut server_builder =
                        TunnelBuilder::with_context(Arc::new(context), forward_addr, client_addr, balancer);

                    if let Some(c) = config.udp_max_associations {
                        server_builder.set_udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        server_builder.set_udp_expiry_duration(d);
                    }
                    server_builder.set_mode(local_config.mode);
                    if let Some(udp_addr) = local_config.udp_addr {
                        server_builder.set_udp_bind_addr(udp_addr);
                    }

                    let server = server_builder.build().await?;
                    local_server.tunnel_servers.push(server);
                }
                #[cfg(feature = "local-http")]
                ProtocolType::Http => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::new(ErrorKind::Other, "http requires local address")),
                    };

                    let builder = HttpBuilder::with_context(Arc::new(context), client_addr, balancer);
                    let server = builder.build().await?;
                    local_server.http_servers.push(server);
                }
                #[cfg(feature = "local-redir")]
                ProtocolType::Redir => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::new(ErrorKind::Other, "redir requires local address")),
                    };

                    let mut server_builder = RedirBuilder::with_context(Arc::new(context), client_addr, balancer);
                    if let Some(c) = config.udp_max_associations {
                        server_builder.set_udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        server_builder.set_udp_expiry_duration(d);
                    }
                    server_builder.set_mode(local_config.mode);
                    server_builder.set_tcp_redir(local_config.tcp_redir);
                    server_builder.set_udp_redir(local_config.udp_redir);
                    if let Some(udp_addr) = local_config.udp_addr {
                        server_builder.set_udp_bind_addr(udp_addr);
                    }

                    let server = server_builder.build().await?;
                    local_server.redir_servers.push(server);
                }
                #[cfg(feature = "local-dns")]
                ProtocolType::Dns => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::new(ErrorKind::Other, "dns requires local address")),
                    };

                    let mut server_builder = {
                        let local_addr = local_config.local_dns_addr;
                        let remote_addr = match local_config.remote_dns_addr.expect("missing remote_dns_addr") {
                            ServerAddr::SocketAddr(addr) => Address::SocketAddress(addr),
                            ServerAddr::DomainName(path, port) => Address::DomainNameAddress(path, port),
                        };

                        DnsBuilder::with_context(Arc::new(context), client_addr, local_addr, remote_addr, balancer)
                    };
                    server_builder.set_mode(local_config.mode);

                    let server = server_builder.build().await?;
                    local_server.dns_servers.push(server);
                }
                #[cfg(any(feature = "local-tun", feature = "wireguard"))]
                ProtocolType::Tun => {
                    #[cfg(unix)]
                    let fd = if let Some(fd) = local_config.tun_device_fd {
                        fd
                    } else if let Some(ref fd_path) = local_config.tun_device_fd_from_path {
                        #[cfg(feature = "local-flow-stat")]
                        let stat_addr = match config.local_stat_addr.as_ref() {
                            Some(local_state_addr) => local_state_addr.clone(),
                            None => return Err(io::Error::new(io::ErrorKind::Other, "tun no local_state_addr for fd")),
                        };

                        Self::read_local_fd(
                            #[cfg(feature = "local-flow-stat")]
                            &stat_addr,
                            fd_path,
                            Duration::from_secs(3),
                        )
                        .await?
                    } else {
                        tracing::error!("no tun fd setted");
                        return Err(io::Error::new(io::ErrorKind::Other, "no tun fd setted"));
                    };

                    #[cfg(feature = "wireguard")]
                    if let ServerProtocol::WG(wg_config) = config.server[0].config.protocol() {
                        let server = wg::Server::create(context, fd, &local_config, wg_config).await?;
                        local_server.wg_server = Some(server);
                        continue;
                    }

                    #[cfg(feature = "local-tun")]
                    {
                        let mut builder = TunBuilder::new(Arc::new(context), balancer);
                        if let Some(address) = local_config.tun_interface_address {
                            builder.address(address);
                        }
                        if let Some(address) = local_config.tun_interface_destination {
                            builder.destination(address);
                        }
                        if let Some(name) = local_config.tun_interface_name {
                            builder.name(&name);
                        }
                        if let Some(c) = config.udp_max_associations {
                            builder.udp_capacity(c);
                        }
                        if let Some(d) = config.udp_timeout {
                            builder.udp_expiry_duration(d);
                        }
                        builder.mode(local_config.mode);
                        builder.file_descriptor(fd);

                        let server = builder.build().await?;
                        local_server.tun_servers.push(server);
                    }
                }
            }
        }

        // 启动一个维护服务，接受运行时控制
        #[cfg(feature = "local-maintain")]
        if let Some(maintain_addr) = config.maintain_addr {
            local_server.maintain_server = Some(maintain::MaintainServer::new(context.clone(), maintain_addr))
        }

        #[cfg(feature = "local-flow-stat")]
        if let Some(local_stat_addr) = config.local_stat_addr {
            local_server.reporter_server = Some(reporter::ReporterServer::create(
                Arc::new(context.clone()),
                cancel_waiter.clone(),
                local_stat_addr,
            ));
        }

        Ok(local_server)
    }

    /// Run local server
    pub async fn run(self) -> io::Result<()> {
        let mut vfut = Vec::new();

        let mut start_stat = StartStat::create();

        for svr in self.socks_servers {
            vfut.push(ServerHandle(tokio::spawn(
                svr.run(start_stat.new_child("socks")).instrument(info_span!("socks")),
            )));
        }

        #[cfg(feature = "local-tunnel")]
        for svr in self.tunnel_servers {
            vfut.push(ServerHandle(tokio::spawn(
                svr.run(start_stat.new_child("tunnel")).instrument(info_span!("tunnel")),
            )));
        }

        #[cfg(feature = "local-http")]
        for svr in self.http_servers {
            vfut.push(ServerHandle(tokio::spawn(
                svr.run(start_stat.new_child("http")).instrument(info_span!("http")),
            )));
        }

        #[cfg(feature = "local-tun")]
        for svr in self.tun_servers {
            vfut.push(ServerHandle(tokio::spawn(
                svr.run(start_stat.new_child("tun")).instrument(info_span!("tun")),
            )));
        }

        #[cfg(feature = "local-dns")]
        for svr in self.dns_servers {
            vfut.push(ServerHandle(tokio::spawn(
                svr.run(start_stat.new_child("dns")).instrument(info_span!("dns")),
            )));
        }

        #[cfg(feature = "local-redir")]
        for svr in self.redir_servers {
            vfut.push(ServerHandle(tokio::spawn(
                svr.run(start_stat.new_child("redir")).instrument(info_span!("redir")),
            )));
        }

        #[cfg(feature = "wireguard")]
        if let Some(svr) = self.wg_server {
            vfut.push(ServerHandle(tokio::spawn(
                svr.run(start_stat.new_child("wg")).instrument(info_span!("wg")),
            )));
        }

        #[cfg(feature = "local-maintain")]
        if let Some(svr) = self.maintain_server {
            vfut.push(ServerHandle(tokio::spawn(
                svr.run(start_stat.new_child("maintain"))
                    .instrument(info_span!("maintain")),
            )));
        }

        #[cfg(feature = "local-flow-stat")]
        if let Some(svr) = self.reporter_server {
            // For Android's flow statistic
            vfut.push(ServerHandle(tokio::spawn(
                svr.run(start_stat).instrument(info_span!("reporter")),
            )));
        } else {
            vfut.push(ServerHandle(tokio::spawn(start_stat.wait())));
        }

        #[cfg(not(feature = "local-flow-stat"))]
        vfut.push(ServerHandle(tokio::spawn(start_stat.wait())));

        run_all_done(vfut).await
    }

    /// Get the internal server balancer
    pub fn server_balancer(&self) -> Option<&PingBalancer> {
        Some(&self.balancer)
    }

    /// Get SOCKS server instances
    pub fn socks_servers(&self) -> &[Socks] {
        &self.socks_servers
    }

    /// Get Tunnel server instances
    #[cfg(feature = "local-tunnel")]
    pub fn tunnel_servers(&self) -> &[Tunnel] {
        &self.tunnel_servers
    }

    /// Get HTTP server instances
    #[cfg(feature = "local-http")]
    pub fn http_servers(&self) -> &[Http] {
        &self.http_servers
    }

    /// Get Tun server instances
    #[cfg(feature = "local-tun")]
    pub fn tun_servers(&self) -> &[Tun] {
        &self.tun_servers
    }

    /// Get DNS server instances
    #[cfg(feature = "local-dns")]
    pub fn dns_servers(&self) -> &[Dns] {
        &self.dns_servers
    }

    /// Get Redir server instances
    #[cfg(feature = "local-redir")]
    pub fn redir_servers(&self) -> &[Redir] {
        &self.redir_servers
    }

    #[cfg(unix)]
    pub async fn read_local_fd(
        #[cfg(feature = "local-flow-stat")] stat_addr: &LocalFlowStatAddress,
        fd_path: &std::path::PathBuf,
        timeout: Duration,
    ) -> io::Result<std::os::fd::RawFd> {
        tokio::select! {
            r = Self::notify_send_fd(#[cfg(feature = "local-flow-stat")] stat_addr, timeout) => {
                r?;
                unreachable!("notify_send_fd should not return success");
            }
            r = Self::recv_fd(fd_path) => {
                r
            }
        }
    }

    #[cfg(unix)]
    async fn recv_fd(fd_path: &std::path::PathBuf) -> io::Result<std::os::fd::RawFd> {
        use shadowsocks::net::UnixListener;
        use std::fs;
        use tokio::io::AsyncWriteExt;

        let _ = fs::remove_file(fd_path);

        let listener = match UnixListener::bind(fd_path) {
            Ok(l) => l,
            Err(err) => {
                tracing::error!("failed to bind uds path \"{}\", error: {}", fd_path.display(), err);
                return Err(err);
            }
        };

        tracing::info!("waiting tun's file descriptor from {}", fd_path.display());

        loop {
            let (mut stream, peer_addr) = listener.accept().await?;

            let mut buffer = [0u8; 1024];
            let mut fd_buffer = [0];

            match stream.recv_with_fd(&mut buffer, &mut fd_buffer).await {
                Ok((n, fd_size)) => {
                    if fd_size == 0 {
                        tracing::error!(
                            "client {:?} didn't send file descriptors with buffer.size {} bytes",
                            peer_addr,
                            n
                        );
                        continue;
                    }

                    tracing::info!("got file descriptor {} for tun from {:?}", fd_buffer[0], peer_addr);

                    if let Err(err) = stream.write_u8(0).await {
                        tracing::error!(err = ?err, "client {:?} send recv fd success error", peer_addr);
                    }

                    return Ok(fd_buffer[0]);
                }
                Err(err) => {
                    tracing::error!(
                        "failed to receive file descriptors from {:?}, error: {}",
                        peer_addr,
                        err
                    );
                }
            }
        }
    }

    #[cfg(feature = "local-flow-stat")]
    async fn notify_send_fd(stat_addr: &LocalFlowStatAddress, timeout: Duration) -> io::Result<()> {
        use tokio::time::Instant;

        let begin = Instant::now();
        reporter::send_local_notify(stat_addr, 2, &[]).await?;
        let elapsed = begin.elapsed();

        if let Some(left_timeout) = timeout.checked_sub(elapsed) {
            tokio::time::sleep(left_timeout).await;
        }

        Err(io::ErrorKind::TimedOut.into())
    }

    #[cfg(not(feature = "local-flow-stat"))]
    async fn notify_send_fd(timeout: Duration) -> io::Result<()> {
        tokio::time::sleep(timeout).await;
        Err(io::ErrorKind::TimedOut.into())
    }
}

async fn run_all_done<T>(mut vfut: Vec<T>) -> io::Result<()>
where
    T: Future<Output = io::Result<()>> + Unpin,
{
    let mut first_res = None;

    while !vfut.is_empty() {
        let (res, _idx, left_vfut) = future::select_all(vfut).await;
        vfut = left_vfut;

        if first_res.is_none() && res.is_err() {
            first_res = Some(res);
        }
    }

    first_res.unwrap_or_else(|| Ok(()))
}

pub async fn create(config: Config, cancel_waiter: CancelWaiter) -> io::Result<Server> {
    let context = Context::new(ServerType::Server);
    let server = Server::new(Arc::new(context), cancel_waiter, config).await?;
    Ok(server)
}

/// Create then run a Local Server
pub async fn run(config: Config, cancel_waiter: CancelWaiter) -> io::Result<()> {
    create(config, cancel_waiter).await?.run().await
}
