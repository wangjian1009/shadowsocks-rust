use super::super::context::ServiceContext;
use serde::{ser::SerializeMap, Serialize, Serializer};
use shadowsocks::ServerAddr;
use std::sync::Arc;

pub struct ServerInfo {
    pub addr: ServerAddr,
    pub context: Arc<ServiceContext>,
}

impl Serialize for ServerInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_map(None)?;

        let addr = self.addr.to_string();
        s.serialize_entry("addr", &addr)?;

        let context = self.context.as_ref();
        let flow_stat = context.flow_stat_ref();
        s.serialize_entry("tx", &flow_stat.tx())?;
        s.serialize_entry("rx", &flow_stat.rx())?;

        s.end()
    }
}
