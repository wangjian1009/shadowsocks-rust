//! Shadowsocks Local Server Context

use std::sync::Arc;

use shadowsocks::{
    config::ServerType,
    context::{Context, SharedContext},
    dns_resolver::DnsResolver,
    net::ConnectOpts,
    relay::Address,
};

use crate::{acl::AccessControl, config::SecurityConfig, net::FlowStat};

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "rate-limit")] {
        use std::time::Duration;
        use shadowsocks::transport::BoundWidth;
    }
}

cfg_if! {
    if #[cfg(feature = "server-mock")] {
        use std::collections::HashMap;

        #[derive(Clone, Copy)]
        pub enum ServerMockProtocol {
            DNS,
        }
    }
}

use super::connection::ConnectionStat;

/// Server Service Context
pub struct ServiceContext {
    context: SharedContext,
    connect_opts: ConnectOpts,

    // Access Control
    acl: Option<Arc<AccessControl>>,

    // Connection statistic report
    connection_stat: Arc<ConnectionStat>,

    // Flow statistic report
    flow_stat: Arc<FlowStat>,

    // Connection rate limit
    #[cfg(feature = "rate-limit")]
    connection_bound_width: Option<BoundWidth>,

    #[cfg(feature = "server-limit")]
    limit_connection_per_ip: Option<u32>,
    #[cfg(feature = "server-limit")]
    limit_connection_close_delay: Option<Duration>,

    #[cfg(feature = "server-mock")]
    mock_servers: Option<HashMap<Address, ServerMockProtocol>>,
}

impl Default for ServiceContext {
    fn default() -> Self {
        ServiceContext {
            context: Context::new_shared(ServerType::Server),
            connect_opts: ConnectOpts::default(),
            acl: None,
            connection_stat: Arc::new(ConnectionStat::new()),
            flow_stat: Arc::new(FlowStat::new()),
            #[cfg(feature = "rate-limit")]
            connection_bound_width: None,
            #[cfg(feature = "server-limit")]
            limit_connection_per_ip: None,
            #[cfg(feature = "server-limit")]
            limit_connection_close_delay: None,
            #[cfg(feature = "server-mock")]
            mock_servers: None,
        }
    }
}

impl ServiceContext {
    /// Create a new `ServiceContext`
    pub fn new() -> ServiceContext {
        ServiceContext::default()
    }

    /// Get cloned `shadowsocks` Context
    pub fn context(&self) -> SharedContext {
        self.context.clone()
    }

    /// Get `shadowsocks` Context reference
    pub fn context_ref(&self) -> &Context {
        self.context.as_ref()
    }

    /// Set `ConnectOpts`
    pub fn set_connect_opts(&mut self, connect_opts: ConnectOpts) {
        self.connect_opts = connect_opts;
    }

    /// Get `ConnectOpts` reference
    pub fn connect_opts_ref(&self) -> &ConnectOpts {
        &self.connect_opts
    }

    /// Set Access Control List
    pub fn set_acl(&mut self, acl: Arc<AccessControl>) {
        self.acl = Some(acl);
    }

    /// Get Access Control List reference
    pub fn acl(&self) -> Option<&AccessControl> {
        self.acl.as_deref()
    }

    /// Set Connection bound width
    #[cfg(feature = "rate-limit")]
    pub fn set_connection_bound_width(&mut self, connection_bound_width: Option<BoundWidth>) {
        self.connection_bound_width = connection_bound_width;
    }

    /// Get Connection bound width
    #[cfg(feature = "rate-limit")]
    pub fn connection_bound_width(&self) -> Option<&BoundWidth> {
        self.connection_bound_width.as_ref()
    }

    #[cfg(feature = "server-limit")]
    pub fn set_limit_connection_per_ip(&mut self, limit_connection_per_ip: Option<u32>) {
        self.limit_connection_per_ip = limit_connection_per_ip;
    }

    #[cfg(feature = "server-limit")]
    pub fn limit_connection_per_ip(&self) -> Option<u32> {
        self.limit_connection_per_ip
    }

    #[cfg(feature = "server-limit")]
    pub fn set_limit_connection_close_delay(&mut self, delay: Option<Duration>) {
        self.limit_connection_close_delay = delay;
    }

    #[cfg(feature = "server-limit")]
    pub fn limit_connection_close_delay(&self) -> Option<&Duration> {
        self.limit_connection_close_delay.as_ref()
    }

    #[cfg(feature = "server-mock")]
    pub fn set_mock_server_protocol(&mut self, addr: Address, protocol: ServerMockProtocol) {
        if self.mock_servers.is_none() {
            self.mock_servers = Some(HashMap::new());
        }

        self.mock_servers.as_mut().unwrap().insert(addr, protocol);
    }

    #[cfg(feature = "server-mock")]
    pub fn mock_server_protocol(&self, addr: &Address) -> Option<ServerMockProtocol> {
        match &self.mock_servers {
            Some(mock_servers) => mock_servers.get(addr).copied(),

            None => None,
        }
    }

    /// Get cloned connection statistic
    pub fn connection_stat(&self) -> Arc<ConnectionStat> {
        self.connection_stat.clone()
    }

    /// Get connection statistic reference
    pub fn connection_stat_ref(&self) -> &ConnectionStat {
        self.connection_stat.as_ref()
    }

    /// Get cloned flow statistic
    pub fn flow_stat(&self) -> Arc<FlowStat> {
        self.flow_stat.clone()
    }

    /// Get flow statistic reference
    pub fn flow_stat_ref(&self) -> &FlowStat {
        self.flow_stat.as_ref()
    }

    /// Set customized DNS resolver
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    /// Get reference of DNS resolver
    pub fn dns_resolver(&self) -> &DnsResolver {
        self.context.dns_resolver()
    }

    /// Check if target should be bypassed
    pub async fn check_outbound_blocked(&self, addr: &Address) -> bool {
        match self.acl {
            None => false,
            Some(ref acl) => acl.check_outbound_blocked(&self.context, addr).await,
        }
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn set_ipv6_first(&mut self, ipv6_first: bool) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set ipv6_first on a shared context");
        context.set_ipv6_first(ipv6_first);
    }

    /// Set security config
    pub fn set_security_config(&mut self, security: &SecurityConfig) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set security on a shared context");
        context.set_replay_attack_policy(security.replay_attack.policy);
    }
}
