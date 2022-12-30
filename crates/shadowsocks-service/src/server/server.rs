//! Shadowsocks Server instance

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use cfg_if::cfg_if;
use futures::FutureExt;
use shadowsocks::{
    canceler::CancelWaiter,
    config::{ManagerAddr, ServerConfig, ServerProtocol, ShadowsocksConfig},
    dns_resolver::DnsResolver,
    net::{AcceptOpts, ConnectOpts, FlowStat},
    plugin::{Plugin, PluginMode},
    transport::direct::TcpConnector,
    ServerAddr,
};
use tokio::{io::AsyncReadExt, time};
use tracing::{debug, debug_span, error, info, info_span, trace, Instrument};

use crate::{acl::AccessControl, config::SecurityConfig};

use super::{
    connection::ConnectionStat, context::ServiceContext, manager::ManagerClient, tcprelay::TcpServer,
    udprelay::UdpServer,
};

#[cfg(feature = "rate-limit")]
use shadowsocks::transport::BoundWidth;

cfg_if! {
    if #[cfg(any(feature = "server-mock"))] {
        use super::context::ServerMockProtocol;
    }
}

/// Shadowsocks Server
pub struct Server {
    context: Arc<ServiceContext>,
    svr_cfg: ServerConfig,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    manager_addr: Option<ManagerAddr>,
    accept_opts: AcceptOpts,
    worker_count: usize,
}

impl Server {
    /// Create a new server from configuration
    pub fn new(cancel_waiter: CancelWaiter, svr_cfg: ServerConfig) -> Server {
        Server::with_context(Arc::new(ServiceContext::new(cancel_waiter)), svr_cfg)
    }

    /// Create a new server with context
    pub fn with_context(context: Arc<ServiceContext>, svr_cfg: ServerConfig) -> Server {
        Server {
            context,
            svr_cfg,
            udp_expiry_duration: None,
            udp_capacity: None,
            manager_addr: None,
            accept_opts: AcceptOpts::default(),
            worker_count: 1,
        }
    }

    pub fn get_context(&self) -> Arc<ServiceContext> {
        self.context.clone()
    }

    /// Get connection statistic
    pub fn connection_stat(&self) -> Arc<ConnectionStat> {
        self.context.connection_stat()
    }

    /// Get connection statistic reference
    pub fn connection_stat_ref(&self) -> &ConnectionStat {
        self.context.connection_stat_ref()
    }

    /// Get flow statistic
    pub fn flow_stat_tcp(&self) -> Arc<FlowStat> {
        self.context.flow_stat_tcp()
    }

    /// Get flow statistic reference
    pub fn flow_stat_tcp_ref(&self) -> &FlowStat {
        self.context.flow_stat_tcp_ref()
    }

    /// Get flow statistic
    pub fn flow_stat_udp(&self) -> Arc<FlowStat> {
        self.context.flow_stat_udp()
    }

    /// Get flow statistic reference
    pub fn flow_stat_udp_ref(&self) -> &FlowStat {
        self.context.flow_stat_udp_ref()
    }

    /// Set `ConnectOpts`
    pub fn set_connect_opts(&mut self, opts: ConnectOpts) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set ConnectOpts on a shared context");
        context.set_connect_opts(opts)
    }

    /// Set Connection bound width
    #[cfg(feature = "rate-limit")]
    pub fn set_connection_bound_width(&mut self, connection_bound_width: Option<BoundWidth>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set connection_bound_width on a shared context");
        context.set_connection_bound_width(connection_bound_width);
    }

    /// Set connection limit per ip
    #[cfg(feature = "server-limit")]
    pub fn set_limit_connection_per_ip(&mut self, limit_connection_per_ip: Option<u32>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set limit_connection_per_ip on a shared context");
        context.set_limit_connection_per_ip(limit_connection_per_ip);
    }

    /// Set limited connection close delay
    #[cfg(feature = "server-limit")]
    pub fn set_limit_connection_close_delay(&mut self, duration: Option<Duration>) {
        let context =
            Arc::get_mut(&mut self.context).expect("cannot set limit_connection_close_delay on a shared context");
        context.set_limit_connection_close_delay(duration);
    }

    #[cfg(feature = "server-mock")]
    pub fn set_mock_server_protocol(&mut self, addr: ServerAddr, protocol: ServerMockProtocol) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set ServerMockProtocol on a shared context");
        context.set_mock_server_protocol(addr, protocol);
    }

    /// Set UDP association's expiry duration
    pub fn set_udp_expiry_duration(&mut self, d: Duration) {
        self.udp_expiry_duration = Some(d);
    }

    /// Set total UDP associations to be kept in one server
    pub fn set_udp_capacity(&mut self, c: usize) {
        self.udp_capacity = Some(c);
    }

    /// Set manager's address to report `stat`
    pub fn set_manager_addr(&mut self, manager_addr: ManagerAddr) {
        self.manager_addr = Some(manager_addr);
    }

    /// Set runtime worker count
    ///
    /// Should be replaced with tokio's metric API when it is stablized.
    /// https://github.com/tokio-rs/tokio/issues/4073
    pub fn set_worker_count(&mut self, worker_count: usize) {
        self.worker_count = worker_count;
    }

    /// Get server's configuration
    pub fn config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    /// Set customized DNS resolver
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    /// Set access control list
    pub fn set_acl(&mut self, acl: Arc<AccessControl>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set ACL on a shared context");
        context.set_acl(acl);
    }

    /// Set `AcceptOpts` for accepting new connections
    pub fn set_accept_opts(&mut self, opts: AcceptOpts) {
        self.accept_opts = opts;
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn set_ipv6_first(&mut self, ipv6_first: bool) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set ipv6_first on a shared context");
        context.set_ipv6_first(ipv6_first);
    }

    /// Set security config
    pub fn set_security_config(&mut self, security: &SecurityConfig) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set security on a shared context");
        context.set_security_config(security)
    }

    /// Start serving
    pub async fn run(mut self) -> io::Result<()> {
        let mut vfut = Vec::with_capacity(3);

        let connector = Arc::new(TcpConnector::new(Some(self.context.context())));

        if self.svr_cfg.if_ss(|ss_cfg| ss_cfg.mode().enable_tcp()).unwrap_or(false) {
            let mut plugin = None;

            if let Some(plugin_cfg) = self.svr_cfg.if_ss(|c| c.plugin()).unwrap_or(None) {
                plugin = Some(Plugin::start(plugin_cfg, self.svr_cfg.addr(), PluginMode::Server)?);
            };

            if let Some(plugin) = plugin {
                self.svr_cfg
                    .must_be_ss_mut(|c| c.set_plugin_addr(plugin.local_addr().into()));
                vfut.push(
                    async move {
                        match plugin.join().await {
                            Ok(status) => {
                                error!("plugin exited with status: {}", status);
                                Ok(())
                            }
                            Err(err) => {
                                error!("plugin exited with error: {}", err);
                                Err(err)
                            }
                        }
                    }
                    .boxed(),
                );
            }

            let tcp_fut = self
                .run_tcp_server(connector.clone())
                .instrument(info_span!("ss.tcp"))
                .boxed();
            vfut.push(tcp_fut);
        }

        if self.svr_cfg.if_ss(|ss_cfg| ss_cfg.mode().enable_udp()).unwrap_or(false) {
            match &self.svr_cfg.protocol() {
                ServerProtocol::SS(cfg) => {
                    let udp_fut = self.run_udp_server(cfg).instrument(info_span!("ss.udp")).boxed();
                    vfut.push(udp_fut);
                }
                #[cfg(feature = "trojan")]
                ServerProtocol::Trojan(_cfg) => {}
                #[cfg(feature = "vless")]
                ServerProtocol::Vless(_cfg) => {}
                #[cfg(feature = "tuic")]
                ServerProtocol::Tuic(_cfg) => {}
            }
        }

        // 其他协议处理
        if self.svr_cfg.if_not_ss() {
            let tcp_fut = self.run_tcp_server(connector.clone()).boxed();
            vfut.push(tcp_fut);

            #[cfg(feature = "tuic")]
            if let ServerProtocol::Tuic(tuic_cfg) = self.svr_cfg.protocol() {
                if let shadowsocks::config::TuicConfig::Server((_, run_noop_tcp)) = tuic_cfg {
                    if *run_noop_tcp {
                        vfut.push(
                            self.tuic_run_shadow_tcp()
                                .instrument(info_span!("tuic.shadow").or_current())
                                .boxed(),
                        );
                    }
                }
            }
        }

        if self.manager_addr.is_some() {
            let manager_fut = self
                .run_manager_report()
                .instrument(
                    info_span!("reporter", remote = self.manager_addr.as_ref().unwrap().to_string()).or_current(),
                )
                .boxed();
            vfut.push(manager_fut);
        }

        // 上报速率测算
        #[cfg(feature = "statistics")]
        vfut.push(self.run_speed_reporter().boxed());

        loop {
            let (res, _, vfut_left) = futures::future::select_all(vfut).await;
            if let Err(err) = res {
                info!(error = ?err, "one server exited error");
                return Err(err);
            }

            if vfut_left.is_empty() {
                return Ok(());
            } else {
                vfut = vfut_left;
            }
        }
    }

    async fn run_tcp_server(&self, connector: Arc<TcpConnector>) -> io::Result<()> {
        let server = TcpServer::new(self.context.clone(), connector, self.accept_opts.clone());
        server.run(&self.svr_cfg).in_current_span().await
    }

    async fn run_udp_server(&self, cfg: &ShadowsocksConfig) -> io::Result<()> {
        let mut server = UdpServer::new(
            self.context.clone(),
            cfg.method(),
            self.udp_expiry_duration,
            self.udp_capacity,
            self.accept_opts.clone(),
        );
        server.set_worker_count(self.worker_count);

        server.run(&self.svr_cfg, cfg).await
    }

    #[cfg(feature = "statistics")]
    async fn run_speed_reporter(&self) -> io::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        const SPEED_DURATION: usize = 30;
        let mut tcp_tx_slots = vec![0u64; SPEED_DURATION];
        let mut tcp_rx_slots = vec![0u64; SPEED_DURATION];
        let mut udp_tx_slots = vec![0u64; SPEED_DURATION];
        let mut udp_rx_slots = vec![0u64; SPEED_DURATION];

        let mut pre_slot: usize = 0;
        let mut pre_tcp_tx: u64 = 0;
        let mut pre_tcp_rx: u64 = 0;
        let mut pre_udp_tx: u64 = 0;
        let mut pre_udp_rx: u64 = 0;

        let bu_context = shadowsocks::statistics::BuContext::new(
            shadowsocks::statistics::ProtocolInfo::from(self.svr_cfg.protocol()),
            self.svr_cfg.acceptor_transport().map(|t| t.tpe()),
        );

        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;

            let now = SystemTime::now();
            let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
            let slot = since_the_epoch.as_secs() as usize % SPEED_DURATION;

            if slot != pre_slot {
                tcp_tx_slots[slot] = 0;
                tcp_rx_slots[slot] = 0;
                udp_tx_slots[slot] = 0;
                udp_rx_slots[slot] = 0;
                pre_slot = slot;
            }

            let tcp_tx = self.context.flow_stat_tcp_ref().tx();
            let tcp_rx = self.context.flow_stat_tcp_ref().rx();
            let udp_tx = self.context.flow_stat_udp_ref().tx();
            let udp_rx = self.context.flow_stat_udp_ref().rx();

            tcp_tx_slots[slot] = tcp_tx_slots[slot] + (tcp_tx - pre_tcp_tx);
            tcp_rx_slots[slot] = tcp_rx_slots[slot] + (tcp_rx - pre_tcp_rx);
            udp_tx_slots[slot] = udp_tx_slots[slot] + (udp_tx - pre_udp_tx);
            udp_rx_slots[slot] = udp_rx_slots[slot] + (udp_rx - pre_udp_rx);

            pre_tcp_tx = tcp_tx;
            pre_tcp_rx = tcp_rx;
            pre_udp_tx = udp_tx;
            pre_udp_rx = udp_rx;

            let total_tcp_tx: u64 = tcp_tx_slots.iter().sum();
            let total_tcp_rx: u64 = tcp_rx_slots.iter().sum();
            let total_udp_tx: u64 = udp_tx_slots.iter().sum();
            let total_udp_rx: u64 = udp_rx_slots.iter().sum();

            bu_context.count_traffic_bps(
                shadowsocks::statistics::METRIC_TRAFFIC_BU_BPS,
                total_tcp_tx as f64 / SPEED_DURATION as f64,
                shadowsocks::statistics::TrafficNet::Tcp,
                shadowsocks::statistics::TrafficWay::Send,
            );
            bu_context.count_traffic_bps(
                shadowsocks::statistics::METRIC_TRAFFIC_BU_BPS,
                total_tcp_rx as f64 / SPEED_DURATION as f64,
                shadowsocks::statistics::TrafficNet::Tcp,
                shadowsocks::statistics::TrafficWay::Recv,
            );
            bu_context.count_traffic_bps(
                shadowsocks::statistics::METRIC_TRAFFIC_BU_BPS,
                total_udp_tx as f64 / SPEED_DURATION as f64,
                shadowsocks::statistics::TrafficNet::Udp,
                shadowsocks::statistics::TrafficWay::Send,
            );
            bu_context.count_traffic_bps(
                shadowsocks::statistics::METRIC_TRAFFIC_BU_BPS,
                total_udp_rx as f64 / SPEED_DURATION as f64,
                shadowsocks::statistics::TrafficNet::Udp,
                shadowsocks::statistics::TrafficWay::Recv,
            );
        }
    }

    async fn run_manager_report(&self) -> io::Result<()> {
        let manager_addr = self.manager_addr.as_ref().unwrap();
        let cancel_waiter = self.context.cancel_waiter();

        loop {
            match ManagerClient::connect(
                self.context.context_ref(),
                manager_addr,
                self.context.connect_opts_ref(),
            )
            .await
            {
                Err(err) => error!(error = ?err, "connect failed"),
                Ok(mut client) => {
                    use super::manager::{ServerStat, StatRequest};

                    let flow_tcp = self.flow_stat_tcp_ref();
                    let flow_udp = self.flow_stat_udp_ref();
                    let connection = self.connection_stat_ref();

                    let addr = match self.svr_cfg.addr() {
                        ServerAddr::SocketAddr(ref addr) => match addr {
                            SocketAddr::V4(ref addr) => {
                                if addr.ip() == &Ipv4Addr::UNSPECIFIED {
                                    format!("{}", addr.port())
                                } else {
                                    format!("{}", addr)
                                }
                            }
                            SocketAddr::V6(ref addr) => format!("{}", addr),
                        },
                        ServerAddr::DomainName(ref path, port) => format!("{}:{}", path, port),
                    };

                    let mut req = StatRequest::new();
                    req.stats.insert(
                        addr,
                        ServerStat {
                            tx: flow_tcp.tx() + flow_udp.tx(),
                            rx: flow_tcp.rx() + flow_udp.rx(),
                            cin: connection.cin(),
                            cout: connection.count(),
                            cin_by_ip: connection.cin_by_ip().await,
                        },
                    );

                    if let Err(err) = client.stat(&req).await {
                        error!(error = ?err, request = ?req, "report error");
                    } else {
                        debug!(request = ?req, "reported");
                    }
                }
            }

            if cancel_waiter.is_canceled() {
                return Ok(());
            }

            // Report every 10 seconds
            tokio::select! {
                _ = time::sleep(Duration::from_secs(10)) => {}
                _ = cancel_waiter.wait() => {}
            }
        }
    }

    pub async fn tuic_run_shadow_tcp(&self) -> io::Result<()> {
        use bytes::BytesMut;
        use shadowsocks::transport::{direct::TcpAcceptor, Acceptor};

        info!("tuic shadow server listening on {}", self.svr_cfg.external_addr());

        let mut listener = TcpAcceptor::bind_server_with_opts(
            self.context.context().as_ref(),
            self.svr_cfg.external_addr(),
            self.accept_opts.clone(),
        )
        .await?;

        let cancel_waiter = self.context.cancel_waiter();
        loop {
            let (mut s, peer_addr) = tokio::select! {
                r = listener.accept() => r?,
                _ = cancel_waiter.wait() => {
                    trace!("canceled");
                    return Ok(());
                }
            };

            let peer_addr = peer_addr.unwrap();

            let span = debug_span!("incoming", peer.addr = peer_addr.to_string());
            tokio::spawn(
                async move {
                    debug!("established");

                    match tokio::time::timeout(tokio::time::Duration::from_secs(1), async move {
                        let mut buffer = BytesMut::with_capacity(10);
                        loop {
                            let n = s.read_buf(&mut buffer).await?;
                            if n == 0 {
                                return io::Result::Ok(());
                            }
                            tracing::trace!("recv {} bytes", n);
                        }
                    })
                    .await
                    {
                        Ok(Ok(())) => debug!("closed by peer"),
                        Ok(Err(err)) => debug!(error = ?err, "closed for error"),
                        Err(err) => debug!(error = ?err, "closed for timeout"),
                    };

                    // read 20 bytes at a time from stream echoing back to stream
                }
                .instrument(span),
            );
        }
    }
}
