use crate::config::{ServerProtocolType, TransportType};

pub enum TrafficWay {
    Send,
    Recv,
}

impl TrafficWay {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Send => "tx",
            Self::Recv => "rx",
        }
    }
}

pub enum TrafficNet {
    Tcp,
    Udp,
}

impl TrafficNet {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone)]
pub struct BuContext {
    protocol: ServerProtocolType,
    transport: Option<TransportType>,
}

impl BuContext {
    pub fn new(protocol: ServerProtocolType, transport: Option<TransportType>) -> Self {
        Self { protocol, transport }
    }

    pub fn count_traffic(&self, key: &'static str, count: u64, net: TrafficNet, way: TrafficWay) {
        counter!(key, count, "way" => way.name(), "net" => net.name(), "proto" => self.protocol.name(), "trans" => self.transport.as_ref().map(|t| t.name()).unwrap_or("none"));
    }
}

mod conn_guard;
pub use conn_guard::{ConnGuard, Target};

mod mon_traffic;
pub use mon_traffic::{MonTraffic, MonTrafficRead, MonTrafficWrite};

pub const METRIC_TCP_CONN_IN: &'static str = "miner_tcp_conn_in_count";
pub const METRIC_TCP_CONN_IN_TOTAL: &'static str = "miner_tcp_conn_in_count_total";
pub const METRIC_TCP_CONN_OUT: &'static str = "miner_tcp_conn_out_count";
pub const METRIC_TCP_CONN_OUT_TOTAL: &'static str = "miner_tcp_conn_out_count_total";

pub const METRIC_UDP_SESSION: &'static str = "miner_udp_session_count";
pub const METRIC_UDP_SESSION_TOTAL: &'static str = "miner_udp_session_count_total";

pub const METRIC_TRAFFIC_BU_TOTAL: &'static str = "miner_traffic_bu_bytes_total";
