mod bu_context;
pub use bu_context::{BuContext, ProtocolInfo, TrafficNet, TrafficWay};

mod conn_guard;
pub use conn_guard::{ConnGuard, Target};

mod mon_traffic;
pub use mon_traffic::{MonTraffic, MonTrafficRead, MonTrafficWrite};

pub const METRIC_TCP_CONN_IN: &str = "miner_tcp_conn_in_count";
pub const METRIC_TCP_CONN_IN_TOTAL: &str = "miner_tcp_conn_in_count_total";
pub const METRIC_TCP_CONN_OUT: &str = "miner_tcp_conn_out_count";
pub const METRIC_TCP_CONN_OUT_TOTAL: &str = "miner_tcp_conn_out_count_total";
pub const METRIC_TCP_CONN_ERR_TOTAL: &str = "miner_tcp_conn_err_count_total";

pub const METRIC_UDP_SESSION: &str = "miner_udp_session_count";
pub const METRIC_UDP_SESSION_TOTAL: &str = "miner_udp_session_count_total";

pub const METRIC_TRAFFIC_BU_TOTAL: &str = "miner_traffic_bu_bytes_total";

pub const METRIC_BU_CLIENT: &str = "miner_client_bu_count";
