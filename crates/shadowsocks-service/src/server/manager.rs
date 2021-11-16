/// Client for communicating with Manager
use std::{collections::HashMap, io::Error};

pub(crate) use log::warn;
use serde::{ser::SerializeMap, Serialize, Serializer};
use shadowsocks::{context::Context, manager::datagram::ManagerDatagram, net::ConnectOpts, ManagerAddr};

#[derive(Serialize, Debug)]
pub struct ServerStat {
    pub tx: u64,
    pub rx: u64,
    pub cin: u32,
    pub cout: u32,
    pub cin_by_ip: u32,
}

#[derive(Debug)]
pub struct StatRequest {
    pub stats: HashMap<String, ServerStat>,
}

impl Serialize for StatRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_map(Some(self.stats.len()))?;
        for (ref k, ref v) in &self.stats {
            s.serialize_entry(k, v)?;
        }
        s.end()
    }
}

impl StatRequest {
    pub fn new() -> StatRequest {
        StatRequest { stats: HashMap::new() }
    }
}

pub struct ManagerClient {
    socket: ManagerDatagram,
}

impl ManagerClient {
    /// Create a `ManagerDatagram` for sending data to manager
    pub async fn connect(
        context: &Context,
        bind_addr: &ManagerAddr,
        connect_opts: &ConnectOpts,
    ) -> Result<ManagerClient, Error> {
        ManagerDatagram::connect(context, bind_addr, connect_opts)
            .await
            .map(|socket| ManagerClient { socket })
            .map_err(Into::into)
    }

    /// Send `stat` report
    pub async fn stat(&mut self, req: &StatRequest) -> Result<(), Error> {
        let req_serialized = serde_json::to_string(&req)?;
        let req_serialized = format!("stat: {}", req_serialized);
        let buf = req_serialized.as_bytes();
        let n = self.socket.send(&buf).await?;
        if n != buf.len() {
            warn!("manager send {} bytes != buffer {} bytes", n, buf.len());
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::{ServerStat, StatRequest};

    #[test]
    pub fn to_json() {
        let mut req = StatRequest::new();
        req.stats.insert(
            "0".to_string(),
            ServerStat {
                tx: 1,
                rx: 2,
                cin: 3,
                cout: 4,
                cin_by_ip: 5,
            },
        );
        let req_serialized = serde_json::to_string(&req).unwrap();
        assert_eq!(
            "stat: {\"0\":{\"tx\":1,\"rx\":2,\"cin\":3,\"cout\":4,\"cin_by_ip\":5}}",
            req_serialized
        );
    }
}
