use crate::config::{ServerProtocolType, TransportType};

#[derive(Clone)]
pub struct BuContext {
    protocol: ServerProtocolType,
    transport: Option<TransportType>,
}

impl BuContext {
    pub fn new(protocol: ServerProtocolType, transport: Option<TransportType>) -> Self {
        Self { protocol, transport }
    }
}

mod in_conn_guard;
pub use in_conn_guard::InConnGuard;

mod mon_traffic;
pub use mon_traffic::{MonTraffic, MonTrafficRead, MonTrafficWrite};
