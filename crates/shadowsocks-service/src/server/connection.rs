use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time,
};

use cfg_if::cfg_if;

use shadowsocks::relay::socks5::Address;
use shadowsocks::{
    net::{AddrCategory, FlowStat},
    ServerAddr,
};

use std::net::{IpAddr, SocketAddr};
use tokio::sync::Mutex;

type ConnectionCounter = AtomicU32;

pub struct ConnectionInfo {
    pub id: u32,
    pub creation_time: time::Instant,
    pub touch_time: Mutex<time::Instant>,
    pub source_addr: SocketAddr,
    pub remote_addr: Mutex<Option<Address>>,
    pub flow: FlowStat,
}

/// Connection statistic
pub struct ConnectionStat {
    out_conn_count: ConnectionCounter,
    in_conn_max: ConnectionCounter,
    in_conn_count: ConnectionCounter,
    in_conns: Mutex<HashMap<u32, Arc<ConnectionInfo>>>,
    #[cfg(feature = "server-limit")]
    in_conns_count_by_source_ip: Mutex<HashMap<IpAddr, u32>>,

    // 业务连接根据IP计数
    bu_conn_by_source_ip: spin::Mutex<HashMap<IpAddr, u32>>,
}

impl Default for ConnectionStat {
    fn default() -> Self {
        ConnectionStat {
            out_conn_count: ConnectionCounter::new(0),
            in_conn_max: ConnectionCounter::new(0),
            in_conn_count: ConnectionCounter::new(0),
            in_conns: Mutex::new(HashMap::new()),

            #[cfg(feature = "server-limit")]
            in_conns_count_by_source_ip: Mutex::new(HashMap::new()),

            bu_conn_by_source_ip: spin::Mutex::new(HashMap::new()),
        }
    }
}

impl ConnectionStat {
    cfg_if! {
        if #[cfg(feature = "server-limit")] {
            #[inline]
            pub async fn cin_by_ip(&self) -> u32 {
                let count = self.in_conns_count_by_source_ip.lock().await.len() as u32;
                if count > 0 {
                    count
                } else {
                    self.cin_by_ip_internal().await
                }
            }

            #[inline]
            pub async fn check_add_in_connection(
                &self,
                source_addr: SocketAddr,
                count_per_ip_limit: Option<u32>,
            ) -> std::io::Result<(Arc<ConnectionInfo>, bool)> {
                match count_per_ip_limit {
                    None => Ok((self.add_in_connection_internal(source_addr).await, false)),
                    Some(count_per_ip_limit) => {
                        self.check_in_connection(&source_addr, count_per_ip_limit).await?;
                        Ok((self.add_in_connection_internal(source_addr).await, true))
                    }
                }
            }

            #[inline]
            pub async fn remove_in_connection(&self, id: &u32, remove_conns_by_source_ip: bool) {
                let connection_info = self.remove_in_connection_internal(id).await;

                if let Some(connection_info) = connection_info {
                    if  remove_conns_by_source_ip {
                        let ip = connection_info.source_addr.ip();
                        let mut in_conns_count_by_source_ip = self.in_conns_count_by_source_ip.lock().await;
                        match in_conns_count_by_source_ip.get_mut(&ip) {
                            None => {},
                            Some(count) => {
                                assert!(*count > 0u32);
                                *count -= 1u32;
                                if *count == 0 {
                                    in_conns_count_by_source_ip.remove(&ip);
                                }
                            }
                        }
                    }
                }
            }

            #[inline]
            async fn check_in_connection(&self, source_addr: &SocketAddr, count_per_ip_limit: u32) -> std::io::Result<()> {
                let gen_error = || {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("connection limit per ip {} reached", count_per_ip_limit))
                };

                let mut in_conns_count_by_source_ip = self.in_conns_count_by_source_ip.lock().await;
                let ip = source_addr.ip();
                match in_conns_count_by_source_ip.get_mut(&ip) {
                    None => {
                        if 0 < count_per_ip_limit {
                            in_conns_count_by_source_ip.insert(ip, 1);
                            Ok(())
                        }
                        else {
                            Err(gen_error())
                        }
                    }
                    Some(count) => {
                        if *count < count_per_ip_limit {
                            *count += 1u32;
                            Ok(())
                        }
                        else {
                            Err(gen_error())
                        }
                    }
                }
            }
        }
        else {
            #[inline]
            pub async fn cin_by_ip(&self) -> u32 {
                self.cin_by_ip_internal().await
            }

            #[inline]
            pub async fn add_in_connection(&self, source_addr: SocketAddr) -> Arc<ConnectionInfo> {
                self.add_in_connection_internal(source_addr).await
            }

            #[inline]
            pub async fn remove_in_connection(&self, id: &u32) {
                self.remove_in_connection_internal(id).await;
            }
        }
    }

    /// Create an empty flow statistic
    pub fn new() -> ConnectionStat {
        ConnectionStat::default()
    }

    /// Incoming connection count
    pub fn cin(&self) -> u32 {
        self.in_conn_count.load(Ordering::Relaxed)
    }

    /// Outgoing connection count
    pub fn count(&self) -> u32 {
        self.out_conn_count.load(Ordering::Relaxed)
    }

    // async fn cin_by_ip_bu(&self) -> u32 {
    //     let bu_conn_by_source_ip = self.bu_conn_by_source_ip.lock().await;
    //     bu_conn_by_source_ip.len() as u32
    // }

    #[inline]
    async fn cin_by_ip_internal(&self) -> u32 {
        let in_conns = self.in_conns.lock().await;

        let mut ips = HashSet::<IpAddr>::new();

        for conn in in_conns.deref().values() {
            ips.insert(conn.source_addr.ip());
        }

        ips.len() as u32
    }

    fn inc_bu_connection(
        &self,
        source_addr: &SocketAddr,
        #[cfg(feature = "statistics")] bu_context: &shadowsocks::statistics::BuContext,
    ) {
        let mut in_conns = self.bu_conn_by_source_ip.lock();
        let ip = source_addr.ip();
        match in_conns.get_mut(&ip) {
            None => {
                in_conns.insert(ip, 1);

                #[cfg(feature = "statistics")]
                bu_context.increment_bu_client();
            }
            Some(count) => {
                *count += 1u32;
            }
        }
    }

    fn dec_bu_connection(
        &self,
        source_addr: &SocketAddr,
        #[cfg(feature = "statistics")] bu_context: &shadowsocks::statistics::BuContext,
    ) {
        let mut in_conns = self.bu_conn_by_source_ip.lock();
        let ip = source_addr.ip();

        match in_conns.get_mut(&ip) {
            None => {
                unreachable!()
            }
            Some(count) => {
                assert!(*count > 0u32);
                *count -= 1u32;
                if *count == 0 {
                    in_conns.remove(&ip);

                    #[cfg(feature = "statistics")]
                    bu_context.increment_bu_client();
                }
            }
        }
    }

    #[inline]
    async fn add_in_connection_internal(&self, source_addr: SocketAddr) -> Arc<ConnectionInfo> {
        self.in_conn_count.fetch_add(1, Ordering::AcqRel);
        let conn_id = self.in_conn_max.fetch_add(1, Ordering::AcqRel);

        let mut in_conns = self.in_conns.lock().await;

        let conn = Arc::new(ConnectionInfo {
            id: conn_id,
            creation_time: time::Instant::now(),
            touch_time: Mutex::new(time::Instant::now()),
            source_addr,
            remote_addr: Mutex::new(None),
            flow: FlowStat::default(),
        });
        in_conns.insert(conn_id, conn.clone());

        conn
    }

    #[inline]
    async fn remove_in_connection_internal(&self, id: &u32) -> Option<Arc<ConnectionInfo>> {
        let mut in_conns = self.in_conns.lock().await;
        let conn = in_conns.remove(id);

        if conn.is_some() {
            self.in_conn_count.fetch_sub(1, Ordering::AcqRel);
        }

        conn
    }

    pub async fn query_in_connections(&self) -> Vec<Arc<ConnectionInfo>> {
        let mut result: Vec<Arc<ConnectionInfo>> = Vec::new();

        let in_conns = self.in_conns.lock().await;

        for value in in_conns.deref().values() {
            result.push(value.clone());
        }

        result
    }

    pub fn add_out_connection(
        self: Arc<ConnectionStat>,
        source_addr: Option<&SocketAddr>,
        target_addr: &ServerAddr,
        #[cfg(feature = "statistics")] bu_context: shadowsocks::statistics::BuContext,
    ) -> OutConnectionGuard {
        let mut bu_addr = None;
        if source_addr.is_some() && Self::is_bu_conn(target_addr) {
            bu_addr = source_addr;
        }

        OutConnectionGuard::new(
            self,
            bu_addr,
            #[cfg(feature = "statistics")]
            shadowsocks::statistics::ConnGuard::new_with_target(
                bu_context,
                shadowsocks::statistics::Target::from(target_addr),
                shadowsocks::statistics::METRIC_TCP_CONN_OUT,
                Some(shadowsocks::statistics::METRIC_TCP_CONN_OUT_TOTAL),
            ),
        )
    }

    fn is_bu_conn(target_addr: &ServerAddr) -> bool {
        let category = AddrCategory::from(target_addr);
        matches!(category, AddrCategory::Public)
    }
}

pub struct OutConnectionGuard {
    stat: Arc<ConnectionStat>,
    source_ip: Option<SocketAddr>,
    #[cfg(feature = "statistics")]
    _out_conn_guard: shadowsocks::statistics::ConnGuard,
}

impl Drop for OutConnectionGuard {
    fn drop(&mut self) {
        self.stat.out_conn_count.fetch_sub(1, Ordering::AcqRel);
        if let Some(ip) = self.source_ip.as_ref() {
            self.stat.dec_bu_connection(ip, self._out_conn_guard.bu_context());
        }
    }
}

impl OutConnectionGuard {
    pub fn new(
        stat: Arc<ConnectionStat>,
        is_bu: Option<&SocketAddr>,
        #[cfg(feature = "statistics")] _out_conn_guard: shadowsocks::statistics::ConnGuard,
    ) -> OutConnectionGuard {
        stat.out_conn_count.fetch_add(1, Ordering::AcqRel);

        let mut source_ip = None;
        if let Some(source_addr) = is_bu {
            stat.inc_bu_connection(source_addr, _out_conn_guard.bu_context());
            source_ip = Some(*source_addr);
        }

        OutConnectionGuard {
            stat,
            source_ip,
            _out_conn_guard,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[tokio::test]
    pub async fn in_conn_guard() {
        let conn_stat = ConnectionStat::default();
        let conn1 = conn_stat
            .add_in_connection_internal("127.0.0.1:8080".parse().unwrap())
            .await;
        let _conn2 = conn_stat
            .add_in_connection_internal("127.0.0.1:8081".parse().unwrap())
            .await;
        let _conn3 = conn_stat
            .add_in_connection_internal("127.0.0.2:8080".parse().unwrap())
            .await;
        assert_eq!(3, conn_stat.cin());
        assert_eq!(2, conn_stat.cin_by_ip().await);

        conn_stat.remove_in_connection_internal(&conn1.id).await;
        assert_eq!(2, conn_stat.cin());
        assert_eq!(2, conn_stat.query_in_connections().await.len());
    }

    #[test]
    pub fn out_conn_guard() {
        let conn_stat = Arc::new(ConnectionStat::default());
        {
            let _guard = conn_stat.clone().add_out_connection(
                Some(&"127.0.0.1:8081".parse().unwrap()),
                &"www.google.com:80".parse().unwrap(),
                #[cfg(feature = "statistics")]
                shadowsocks::statistics::BuContext::new(
                    shadowsocks::statistics::ProtocolInfo::SS {
                        method: "test-method".to_string(),
                    },
                    None,
                ),
            );
            assert_eq!(1, conn_stat.count());
        }
        assert_eq!(0, conn_stat.count());
    }

    #[cfg(feature = "server-limit")]
    #[tokio::test]
    pub async fn cin_by_ip_no_limit() {
        let conn_stat = ConnectionStat::default();
        let (_conn1, _guard1) = conn_stat
            .check_add_in_connection("127.0.0.1:8080".parse().unwrap(), None)
            .await
            .unwrap();
        assert_eq!(false, _guard1);

        let (_conn2, _guard2) = conn_stat
            .check_add_in_connection("127.0.0.1:8081".parse().unwrap(), None)
            .await
            .unwrap();
        let (_conn3, _guard3) = conn_stat
            .check_add_in_connection("127.0.0.2:8080".parse().unwrap(), None)
            .await
            .unwrap();

        assert_eq!(3, conn_stat.cin());
        assert_eq!(2, conn_stat.cin_by_ip().await);

        conn_stat.remove_in_connection(&_conn1.id, _guard1).await;
        assert_eq!(2, conn_stat.cin());
        assert_eq!(2, conn_stat.cin_by_ip().await);

        conn_stat.remove_in_connection(&_conn2.id, _guard2).await;
        assert_eq!(1, conn_stat.cin());
        assert_eq!(1, conn_stat.cin_by_ip().await);

        // 删除不存在的
        conn_stat.remove_in_connection(&_conn2.id, _guard2).await;
        assert_eq!(1, conn_stat.cin());
        assert_eq!(1, conn_stat.cin_by_ip().await);
    }

    #[cfg(feature = "server-limit")]
    #[tokio::test]
    pub async fn cin_by_ip_with_limit() {
        let conn_stat = ConnectionStat::default();
        let (_conn1, _guard1) = conn_stat
            .check_add_in_connection("127.0.0.1:8080".parse().unwrap(), Some(2u32))
            .await
            .unwrap();
        assert_eq!(true, _guard1);

        let (_conn2, _guard2) = conn_stat
            .check_add_in_connection("127.0.0.1:8081".parse().unwrap(), Some(2u32))
            .await
            .unwrap();
        let (_conn3, _guard3) = conn_stat
            .check_add_in_connection("127.0.0.2:8080".parse().unwrap(), Some(2u32))
            .await
            .unwrap();

        assert_eq!(3, conn_stat.cin());
        assert_eq!(2, conn_stat.cin_by_ip().await);

        conn_stat.remove_in_connection(&_conn1.id, _guard1).await;
        assert_eq!(2, conn_stat.cin());
        assert_eq!(2, conn_stat.cin_by_ip().await);

        conn_stat.remove_in_connection(&_conn2.id, _guard2).await;
        assert_eq!(1, conn_stat.cin());
        assert_eq!(1, conn_stat.cin_by_ip().await);

        // 删除不存在的
        conn_stat.remove_in_connection(&_conn2.id, _guard2).await;
        assert_eq!(1, conn_stat.cin());
        assert_eq!(1, conn_stat.cin_by_ip().await);
    }
}
