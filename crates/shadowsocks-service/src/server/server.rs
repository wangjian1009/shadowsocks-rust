//! Shadowsocks Server instance

use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use cfg_if::cfg_if;
use futures::{stream::FuturesUnordered, FutureExt, StreamExt};
use log::{error, trace};
use shadowsocks::{
    config::{ManagerAddr, ServerConfig},
    dns_resolver::DnsResolver,
    net::{AcceptOpts, ConnectOpts},
    plugin::{Plugin, PluginMode},
    ServerAddr,
};
use tokio::time;

use crate::{acl::AccessControl, config::SecurityConfig, net::FlowStat};

use super::{
    connection::ConnectionStat,
    context::ServiceContext,
    manager::ManagerClient,
    tcprelay::TcpServer,
    udprelay::UdpServer,
};

#[cfg(feature = "rate-limit")]
use crate::net::BoundWidth;

cfg_if! {
    if #[cfg(any(feature = "server-mock"))] {
        use shadowsocks::relay::socks5::Address;
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
}

impl Server {
    /// Create a new server from configuration
    pub fn new(svr_cfg: ServerConfig) -> Server {
        Server::with_context(Arc::new(ServiceContext::new()), svr_cfg)
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
    pub fn flow_stat(&self) -> Arc<FlowStat> {
        self.context.flow_stat()
    }

    /// Get flow statistic reference
    pub fn flow_stat_ref(&self) -> &FlowStat {
        self.context.flow_stat_ref()
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
    pub fn set_mock_server_protocol(&mut self, addr: Address, protocol: ServerMockProtocol) {
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
        let vfut = FuturesUnordered::new();

        if self.svr_cfg.mode().enable_tcp() {
            if let Some(plugin_cfg) = self.svr_cfg.plugin() {
                let plugin = Plugin::start(plugin_cfg, self.svr_cfg.addr(), PluginMode::Server)?;
                self.svr_cfg.set_plugin_addr(plugin.local_addr().into());
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

            let tcp_fut = self.run_tcp_server().boxed();
            vfut.push(tcp_fut);
        }

        if self.svr_cfg.mode().enable_udp() {
            let udp_fut = self.run_udp_server().boxed();
            vfut.push(udp_fut);
        }

        if self.manager_addr.is_some() {
            let manager_fut = self.run_manager_report().boxed();
            vfut.push(manager_fut);
        }

        let (res, _) = vfut.into_future().await;
        if let Some(Err(err)) = res {
            error!("servers exited with error: {}", err);
        }

        let err = io::Error::new(ErrorKind::Other, "server exited unexpectedly");
        Err(err)
    }

    async fn run_tcp_server(&self) -> io::Result<()> {
        let server = TcpServer::new(self.context.clone(), self.accept_opts.clone());
        server.run(&self.svr_cfg).await
    }

    async fn run_udp_server(&self) -> io::Result<()> {
        let server = UdpServer::new(
            self.context.clone(),
            self.udp_expiry_duration,
            self.udp_capacity,
            self.accept_opts.clone(),
        );
        server.run(&self.svr_cfg).await
    }

    async fn run_manager_report(&self) -> io::Result<()> {
        let manager_addr = self.manager_addr.as_ref().unwrap();

        loop {
            match ManagerClient::connect(
                self.context.context_ref(),
                manager_addr,
                self.context.connect_opts_ref(),
            )
            .await
            {
                Err(err) => {
                    error!("failed to connect manager {}, error: {}", manager_addr, err);
                }
                Ok(mut client) => {
                    use super::manager::{ServerStat, StatRequest};

                    let flow = self.flow_stat_ref();
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
                            tx: flow.tx(),
                            rx: flow.rx(),
                            cin: connection.cin(),
                            cout: connection.count(),
                            cin_by_ip: connection.cin_by_ip().await,
                        },
                    );

                    if let Err(err) = client.stat(&req).await {
                        error!(
                            "failed to send stat to manager {}, error: {}, {:?}",
                            manager_addr, err, req
                        );
                    } else {
                        trace!("report to manager {}, {:?}", manager_addr, req);
                    }
                }
            }

            // Report every 10 seconds
            time::sleep(Duration::from_secs(10)).await;
        }
    }
}
