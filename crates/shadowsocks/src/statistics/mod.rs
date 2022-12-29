mod bu_context;
pub use bu_context::{BuContext, ProtocolInfo, TrafficNet, TrafficWay};

mod conn_guard;
pub use conn_guard::{ConnGuard, Target};

mod mon_traffic;
pub use mon_traffic::{MonTraffic, MonTrafficRead, MonTrafficWrite};

pub const METRIC_TCP_CONN_IN: &'static str = "miner_tcp_conn_in_count";
pub const METRIC_TCP_CONN_IN_TOTAL: &'static str = "miner_tcp_conn_in_count_total";
pub const METRIC_TCP_CONN_OUT: &'static str = "miner_tcp_conn_out_count";
pub const METRIC_TCP_CONN_OUT_TOTAL: &'static str = "miner_tcp_conn_out_count_total";
pub const METRIC_TCP_CONN_ERR_TOTAL: &'static str = "miner_tcp_conn_err_count_total";

pub const METRIC_UDP_SESSION: &'static str = "miner_udp_session_count";
pub const METRIC_UDP_SESSION_TOTAL: &'static str = "miner_udp_session_count_total";

pub const METRIC_TRAFFIC_BU_TOTAL: &'static str = "miner_traffic_bu_bytes_total";
