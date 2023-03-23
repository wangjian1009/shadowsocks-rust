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
    config::{Mode, ServerType},
    context::Context,
    net::{AcceptOpts, ConnectOpts},
    relay::socks5::Address,
};
use tokio::task::JoinHandle;
use tracing::{info, info_span, trace, warn, Instrument};

#[cfg(feature = "local-flow-stat")]
use crate::config::LocalFlowStatAddress;
use crate::{
    config::{Config, ConfigType, ProtocolType},
    dns::build_dns_resolver,
};

#[cfg(feature = "local-maintain")]
mod maintain;

/// 解析证书等可以脱离Android运行，环境相关在模块内区分
pub mod android;

#[cfg(feature = "local-flow-stat")]
use shadowsocks::net::FlowStat;

use self::{
    context::ServiceContext,
    loadbalancing::{PingBalancer, PingBalancerBuilder},
};

pub mod api;
pub mod context;
#[cfg(feature = "local-dns")]
pub mod dns;
#[cfg(feature = "local-http")]
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
    vfut: Vec<ServerHandle>,
    balancer: Option<PingBalancer>,
}

impl Server {
    /// Create a shadowsocks local server
    pub async fn create(config: Config, cancel_waiter: CancelWaiter) -> io::Result<Server> {
        create(config, cancel_waiter).await
    }

    /// Run local server
    pub async fn run(mut self) -> io::Result<()> {
        loop {
            let (res, _, vfut_left) = future::select_all(self.vfut).await;
            res?;

            if vfut_left.is_empty() {
                return Ok(());
            } else {
                info!("one server exited success, left {}", vfut_left.len());
                self.vfut = vfut_left;
            }
        }
    }

    /// Wait until any of the servers were exited
    pub async fn wait_until_exit(self) -> io::Result<()> {
        let (res, ..) = future::select_all(self.vfut).await;
        res
    }

    /// Get the internal server balancer
    pub fn server_balancer(&self) -> Option<&PingBalancer> {
        self.balancer.as_ref()
    }
}

/// Starts a shadowsocks local server
pub async fn create(config: Config, cancel_waiter: CancelWaiter) -> io::Result<Server> {
    assert!(config.config_type == ConfigType::Local && !config.local.is_empty());

    trace!("{:?}", config);

    // Warning for Stream Ciphers
    #[cfg(feature = "stream-cipher")]
    for inst in config.server.iter() {
        let server = &inst.config;

        server.if_ss(|ss_cfg| {
            if ss_cfg.method().is_stream() {
                warn!("stream cipher {} for server {} have inherent weaknesses (see discussion in https://github.com/shadowsocks/shadowsocks-org/issues/36). \
                            DO NOT USE. It will be removed in the future.", ss_cfg.method(), server.addr());
            }
        });
    }

    #[cfg(all(unix, not(target_os = "android")))]
    if let Some(nofile) = config.nofile {
        use crate::sys::set_nofile;
        if let Err(err) = set_nofile(nofile) {
            warn!("set_nofile {} failed, error: {}", nofile, err);
        }
    }

    // Global ServiceContext template
    // Each Local instance will hold a copy of its fields
    let context = Context::new_shared(ServerType::Local);
    let mut context = ServiceContext::new(context, cancel_waiter.clone());

    let mut connect_opts = ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path.clone(),

        bind_interface: config.outbound_bind_interface.clone(),
        bind_local_addr: config.outbound_bind_addr,

        ..Default::default()
    };
    connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
    connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
    connect_opts.tcp.nodelay = config.no_delay;
    connect_opts.tcp.fastopen = config.fast_open;
    connect_opts.tcp.keepalive = config.keep_alive.or(Some(LOCAL_DEFAULT_KEEPALIVE_TIMEOUT));
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
    context.set_accept_opts(accept_opts);

    if let Some(resolver) = build_dns_resolver(config.dns.clone(), config.ipv6_first, context.connect_opts_ref()).await
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
        info!("bound-width={}", bound_width);
        context.rate_limiter().set_rate_limit(Some(bound_width.clone()))?;
    }

    #[cfg(feature = "sniffer-bittorrent")]
    if let Some(reject_bittorrent) = config.reject_bittorrent {
        info!("reject bittorrent = {}", reject_bittorrent);
        if reject_bittorrent {
            context.set_protocol_action(SnifferProtocol::Bittorrent, Some(ProtocolAction::Reject));
            context.set_protocol_action(SnifferProtocol::Utp, Some(ProtocolAction::Reject));
        }
    }

    let mut vfut = Vec::new();

    #[cfg(feature = "local-flow-stat")]
    if let Some(stat_addr) = config.local_stat_addr {
        // For Android's flow statistic

        let report_fut = flow_report_task(stat_addr, context.cancel_waiter(), context.flow_stat());
        vfut.push(ServerHandle(tokio::spawn(
            report_fut.instrument(info_span!("flow-report")),
        )));
    }

    // 启动一个维护服务，接受运行时控制
    #[cfg(feature = "local-maintain")]
    if let Some(maintain_addr) = config.maintain_addr {
        let maintain_server = maintain::MaintainServer::new(context.clone());
        vfut.push(ServerHandle(tokio::spawn(
            maintain_server.run(maintain_addr).instrument(info_span!("maintain")),
        )));
    }

    #[cfg(all(feature = "local-fake-mode", target_os = "android"))]
    {
        let mut context = context.clone();
        vfut.push(ServerHandle(tokio::spawn(
            async move {
                tokio::time::sleep(Duration::from_millis(500 + rand::random::<u64>() % 1500)).await;
                let result = crate::local::android::validate_sign();
                if result.error.is_some() {
                    context.set_fake_mode(crate::local::context::FakeMode::ParamError);
                }

                futures::future::pending::<()>().await;
                panic!("check completed");
            }
            .instrument(info_span!("fake")),
        )));
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

    #[cfg(feature = "wireguard")]
    if config.server.len() == 1 {
        use shadowsocks::config::ServerProtocol;
        if let ServerProtocol::WG(wg_config) = config.server[0].config.protocol() {
            wg::create_wg_server(context, &mut vfut, config.local, wg_config).await?;
            return Ok(Server { vfut, balancer: None });
        }
    }

    assert!(!config.local.is_empty(), "no valid local server configuration");

    // Create a service balancer for choosing between multiple servers
    let balancer = {
        let mut mode = Mode::TcpOnly;

        for local in &config.local {
            mode = mode.merge(local.config.mode);
        }

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

        for server in config.server {
            if let Err(err) = balancer_builder.add_server(server.config) {
                warn!("add server failed, error: {}", err);
            }
        }

        balancer_builder.build().await?
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

        let context = Arc::new(context);
        let balancer = balancer.clone();

        match local_config.protocol {
            ProtocolType::Socks => {
                use self::socks::Socks;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "socks requires local address")),
                };

                let mut server = Socks::with_context(context.clone());
                server.set_mode(local_config.mode);
                server.set_socks5_auth(local_config.socks5_auth);

                if let Some(c) = config.udp_max_associations {
                    server.set_udp_capacity(c);
                }
                if let Some(d) = config.udp_timeout {
                    server.set_udp_expiry_duration(d);
                }
                if let Some(b) = local_config.udp_addr {
                    server.set_udp_bind_addr(b.clone());
                }

                vfut.push(ServerHandle(tokio::spawn(
                    async move { server.run(&client_addr, balancer).await }.instrument(info_span!("socks")),
                )));
            }
            #[cfg(feature = "local-tunnel")]
            ProtocolType::Tunnel => {
                use self::tunnel::Tunnel;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "tunnel requires local address")),
                };

                let forward_addr = local_config.forward_addr.expect("tunnel requires forward address");

                let mut server = Tunnel::with_context(context.clone(), Address::from(forward_addr.clone()));

                if let Some(c) = config.udp_max_associations {
                    server.set_udp_capacity(c);
                }
                if let Some(d) = config.udp_timeout {
                    server.set_udp_expiry_duration(d);
                }
                server.set_mode(local_config.mode);

                let udp_addr = local_config.udp_addr.unwrap_or_else(|| client_addr.clone());
                vfut.push(ServerHandle(tokio::spawn(
                    async move { server.run(&client_addr, &udp_addr, balancer).await }.instrument(info_span!("tunnel")),
                )));
            }
            #[cfg(feature = "local-http")]
            ProtocolType::Http => {
                use self::http::Http;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "http requires local address")),
                };

                let server = Http::with_context(context.clone());
                vfut.push(ServerHandle(tokio::spawn(
                    async move { server.run(&client_addr, balancer).await }.instrument(info_span!("http")),
                )));
            }
            #[cfg(feature = "local-redir")]
            ProtocolType::Redir => {
                use self::redir::Redir;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "redir requires local address")),
                };

                let mut server = Redir::with_context(context.clone());
                if let Some(c) = config.udp_max_associations {
                    server.set_udp_capacity(c);
                }
                if let Some(d) = config.udp_timeout {
                    server.set_udp_expiry_duration(d);
                }
                server.set_mode(local_config.mode);
                server.set_tcp_redir(local_config.tcp_redir);
                server.set_udp_redir(local_config.udp_redir);

                let udp_addr = local_config.udp_addr.unwrap_or_else(|| client_addr.clone());
                vfut.push(ServerHandle(tokio::spawn(
                    async move { server.run(&client_addr, &udp_addr, balancer).await }.instrument(info_span!("redir")),
                )));
            }
            #[cfg(feature = "local-dns")]
            ProtocolType::Dns => {
                use self::dns::Dns;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "dns requires local address")),
                };

                let mut server = {
                    let local_addr = local_config.local_dns_addr.expect("missing local_dns_addr");
                    let remote_addr = local_config.remote_dns_addr.expect("missing remote_dns_addr");

                    Dns::with_context(context.clone(), local_addr.clone(), Address::from(remote_addr.clone()))
                };
                server.set_mode(local_config.mode);

                vfut.push(ServerHandle(tokio::spawn(
                    async move { server.run(&client_addr, balancer).await }.instrument(info_span!("dns")),
                )));
            }
            #[cfg(feature = "local-tun")]
            ProtocolType::Tun => {
                use shadowsocks::net::UnixListener;

                use self::tun::TunBuilder;

                let mut builder = TunBuilder::new(context.clone(), balancer);
                if let Some(address) = local_config.tun_interface_address {
                    builder = builder.address(address);
                }
                if let Some(address) = local_config.tun_interface_destination {
                    builder = builder.destination(address);
                }
                if let Some(name) = local_config.tun_interface_name {
                    builder = builder.name(&name);
                }
                if let Some(c) = config.udp_max_associations {
                    builder = builder.udp_capacity(c);
                }
                if let Some(d) = config.udp_timeout {
                    builder = builder.udp_expiry_duration(d);
                }
                builder = builder.mode(local_config.mode);
                #[cfg(unix)]
                if let Some(fd) = local_config.tun_device_fd {
                    builder = builder.file_descriptor(fd);
                } else if let Some(ref fd_path) = local_config.tun_device_fd_from_path {
                    use std::fs;

                    let _ = fs::remove_file(fd_path);

                    let listener = match UnixListener::bind(fd_path) {
                        Ok(l) => l,
                        Err(err) => {
                            tracing::error!("failed to bind uds path \"{}\", error: {}", fd_path.display(), err);
                            return Err(err);
                        }
                    };

                    info!("waiting tun's file descriptor from {}", fd_path.display());

                    loop {
                        let (mut stream, peer_addr) = listener.accept().await?;
                        trace!("accepted {:?} for receiving tun file descriptor", peer_addr);

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

                                info!("got file descriptor {} for tun from {:?}", fd_buffer[0], peer_addr);

                                builder = builder.file_descriptor(fd_buffer[0]);
                                break;
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
                let server = builder.build().await?;
                vfut.push(ServerHandle(tokio::spawn(
                    async move { server.run().await }.instrument(info_span!("tun")),
                )));
            }
            #[cfg(all(not(feature = "local-tun"), feature = "wireguard"))]
            ProtocolType::Tun => {
                unimplemented!()
            }
        }
    }

    Ok(Server {
        vfut,
        balancer: Some(balancer),
    })
}

#[cfg(feature = "local-flow-stat")]
async fn flow_report_task(
    stat_addr: LocalFlowStatAddress,
    cancel_waiter: CancelWaiter,
    flow_stat: Arc<FlowStat>,
) -> io::Result<()> {
    use std::slice;

    use tokio::{io::AsyncWriteExt, time};
    use tracing::debug;

    // Local flow statistic report RPC
    let timeout = Duration::from_secs(1);

    loop {
        // keep it as libev's default, 0.5 seconds
        tokio::select! {
            _ = time::sleep(Duration::from_millis(500)) => {
            }
            _ = cancel_waiter.wait() => {
                trace!("canceled");
                return Ok(());
            }
        }
        time::sleep(Duration::from_millis(500)).await;

        let tx = flow_stat.tx();
        let rx = flow_stat.rx();

        let buf: [u64; 2] = [tx, rx];
        let buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const _, 16) };

        match stat_addr {
            #[cfg(unix)]
            LocalFlowStatAddress::UnixStreamPath(ref stat_path) => {
                use tokio::net::UnixStream;

                let mut stream = match time::timeout(timeout, UnixStream::connect(stat_path)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(err)) => {
                        debug!("send client flow statistic error: {}", err);
                        continue;
                    }
                    Err(..) => {
                        debug!("send client flow statistic error: timeout");
                        continue;
                    }
                };

                match time::timeout(timeout, stream.write_all(buf)).await {
                    Ok(Ok(..)) => {}
                    Ok(Err(err)) => {
                        debug!("send client flow statistic error: {}", err);
                    }
                    Err(..) => {
                        debug!("send client flow statistic error: timeout");
                    }
                }
            }
            LocalFlowStatAddress::TcpStreamAddr(stat_addr) => {
                use tokio::net::TcpStream;

                let mut stream = match time::timeout(timeout, TcpStream::connect(stat_addr)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(err)) => {
                        debug!("send client flow statistic error: {}", err);
                        continue;
                    }
                    Err(..) => {
                        debug!("send client flow statistic error: timeout");
                        continue;
                    }
                };

                match time::timeout(timeout, stream.write_all(buf)).await {
                    Ok(Ok(..)) => {}
                    Ok(Err(err)) => {
                        debug!("send client flow statistic error: {}", err);
                    }
                    Err(..) => {
                        debug!("send client flow statistic error: timeout");
                    }
                }
            }
        }
    }
}

/// Create then run a Local Server
pub async fn run(config: Config, cancel_waiter: CancelWaiter) -> io::Result<()> {
    create(config, cancel_waiter).await?.wait_until_exit().await
}
