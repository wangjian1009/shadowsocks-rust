use std::sync::atomic::Ordering;

// use std::net::IpAddr;
// use tokio::sync::Mutex;

type ConnectionCounter = std::sync::atomic::AtomicU32;

/// Connection statistic
pub struct ConnectionStat {
    out_count: ConnectionCounter,
    in_count: ConnectionCounter,
    // in_conns: Mutex<HashMap<IpAddr, u32>>,
}

impl Default for ConnectionStat {
    fn default() -> Self {
        ConnectionStat {
            out_count: ConnectionCounter::new(0),
            in_count: ConnectionCounter::new(0),
            // in_conns: Mutex::new(HashMap::new()),
        }
    }
}

impl ConnectionStat {
    /// Create an empty flow statistic
    pub fn new() -> ConnectionStat {
        ConnectionStat::default()
    }

    /// Incoming connection count
    pub fn cin(&self) -> u32 {
        self.in_count.load(Ordering::Relaxed)
    }

    /// Outgoing connection count
    pub fn count(&self) -> u32 {
        self.out_count.load(Ordering::Relaxed)
    }

    // pub async fn add_in_connection(&self, addr: &IpAddr) {
    //     let mut in_conns = self.in_conns.lock().await;
    //     let count = in_conns.entry(*addr).or_insert(0);
    //     *count += 1;
    // }

    // pub async fn remove_in_connection(&self, addr: &IpAddr) {
    //     let conns = self.in_conns.lock().await;
    // }

    pub fn add_in_connection(&self) {
        self.in_count.fetch_add(1, Ordering::AcqRel);
    }

    pub fn remove_in_connection(&self) {
        self.in_count.fetch_sub(1, Ordering::AcqRel);
    }

    pub fn add_out_connection(&self) {
        self.out_count.fetch_add(1, Ordering::AcqRel);
    }

    pub fn remove_out_connection(&self) {
        self.out_count.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct InConnectionGuard<'a> {
    stat: &'a ConnectionStat,
}

impl<'a> Drop for InConnectionGuard<'a> {
    fn drop(&mut self) {
        self.stat.remove_in_connection();
    }
}

impl<'a> InConnectionGuard<'a> {
    pub fn new(stat: &'a ConnectionStat) -> InConnectionGuard {
        stat.add_in_connection();
        InConnectionGuard { stat }
    }
}

pub struct OutConnectionGuard<'a> {
    stat: &'a ConnectionStat,
}

impl<'a> Drop for OutConnectionGuard<'a> {
    fn drop(&mut self) {
        self.stat.remove_out_connection();
    }
}

impl<'a> OutConnectionGuard<'a> {
    pub fn new(stat: &'a ConnectionStat) -> OutConnectionGuard {
        stat.add_out_connection();
        OutConnectionGuard { stat }
    }
}

#[cfg(test)]
pub mod tests {
    use super::{ConnectionStat, OutConnectionGuard};

    #[test]
    pub fn out_conn_basic() {
        let conn_stat = ConnectionStat::default();
        conn_stat.add_out_connection();
        assert_eq!(1, conn_stat.count());
    }

    #[test]
    pub fn out_conn_guard() {
        let conn_stat = ConnectionStat::default();
        {
            let _guard = OutConnectionGuard::new(&conn_stat);
            assert_eq!(1, conn_stat.count());
        }
        assert_eq!(0, conn_stat.count());
    }
}
