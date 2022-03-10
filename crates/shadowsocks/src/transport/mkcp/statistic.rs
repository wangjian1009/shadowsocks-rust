//! Server flow statistic

use std::{
    fmt::{self, Display},
    sync::atomic::Ordering,
};

#[cfg(not(any(target_arch = "mips", target_arch = "powerpc")))]
type StatisticCounter = std::sync::atomic::AtomicU64;
#[cfg(any(target_arch = "mips", target_arch = "powerpc"))]
type StatisticCounter = std::sync::atomic::AtomicU32;

/// Connection flow statistic
pub struct StatisticStat {
    tx_retry: StatisticCounter,
    tx_first: StatisticCounter,
    rx_first: StatisticCounter,
    rx_ignore: StatisticCounter,
}

impl Default for StatisticStat {
    fn default() -> Self {
        StatisticStat {
            tx_retry: StatisticCounter::new(0),
            tx_first: StatisticCounter::new(0),
            rx_first: StatisticCounter::new(0),
            rx_ignore: StatisticCounter::new(0),
        }
    }
}

impl Display for StatisticStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tx_retry = self.tx_retry();
        let tx_first = self.tx_first();
        let rx_first = self.rx_first();
        let rx_ignore = self.rx_ignore();

        let tx_total = tx_first + tx_retry;
        let tx_rate = if tx_total > 0 {
            tx_retry as f32 / tx_total as f32
        } else {
            0.0
        };

        let rx_total = rx_first + rx_ignore;
        let rx_rate = if rx_total > 0 {
            rx_ignore as f32 / rx_total as f32
        } else {
            0.0
        };

        write!(
            f,
            "tx={}(lost={} {}), rx={}(ignore={} {})",
            tx_total, tx_retry, tx_rate, rx_total, rx_ignore, rx_rate,
        )
    }
}

impl StatisticStat {
    #[inline]
    pub fn new() -> StatisticStat {
        StatisticStat::default()
    }

    #[inline]
    pub fn tx_retry(&self) -> u64 {
        self.tx_retry.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn incr_tx_retry(&self, n: u64) {
        self.tx_retry.fetch_add(n as _, Ordering::AcqRel);
    }

    #[inline]
    pub fn tx_first(&self) -> u64 {
        self.tx_first.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn incr_tx_first(&self, n: u64) {
        self.tx_first.fetch_add(n as _, Ordering::AcqRel);
    }

    #[inline]
    pub fn rx_first(&self) -> u64 {
        self.rx_first.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn incr_rx_first(&self, n: u64) {
        self.rx_first.fetch_add(n as _, Ordering::AcqRel);
    }

    #[inline]
    pub fn rx_ignore(&self) -> u64 {
        self.rx_ignore.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn incr_rx_ignore(&self, n: u64) {
        self.rx_ignore.fetch_add(n as _, Ordering::AcqRel);
    }
}
