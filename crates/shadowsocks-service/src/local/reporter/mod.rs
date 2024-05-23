use std::sync::Arc;
use tokio::{
    io,
    time::{self, Duration},
};

use shadowsocks::canceler::Canceler;

use crate::{
    config::LocalFlowStatAddress,
    local::{ServiceContext, StartStat},
};

pub struct ReporterServer {
    context: Arc<ServiceContext>,
    stat_addr: LocalFlowStatAddress,
}

impl ReporterServer {
    pub fn create(context: Arc<ServiceContext>, stat_addr: LocalFlowStatAddress) -> Self {
        Self { context, stat_addr }
    }

    pub async fn run(self, start_stat: StartStat, canceler: Arc<Canceler>) -> io::Result<()> {
        let mut cancel_waiter = canceler.waiter();
        tokio::select! {
            r = self.do_run(start_stat) => {
                r
            }
            _ = cancel_waiter.wait() => {
                tracing::info!("reporter processor canceled");
                return Ok(());
            }
        }
    }

    pub async fn do_run(self, start_stat: StartStat) -> io::Result<()> {
        let _ = start_stat.wait().await?;
        send_local_notify(&self.stat_addr, 3, &[]).await?;

        // keep it as libev's default, 0.5 seconds
        const REPORT_SPAN_MS: u64 = 500; // 上报间隔
        const SPEED_SLOT_DURATION_MS: u64 = 100; // 速度统计点间隔
        const SPEED_SLOT_COUNT: usize = 10; // 速度统计点数量

        // 实际速度统计周期是  * SPEED_SLOT_COUNT = 1000ms
        
        let mut tx_slots = vec![0u64; SPEED_SLOT_COUNT];
        let mut rx_slots = vec![0u64; SPEED_SLOT_COUNT];

        let mut pre_slot: usize = 0;
        let mut pre_tx: u64 = 0;
        let mut pre_rx: u64 = 0;

        // Local flow statistic report RPC
        let flow_stat = self.context.flow_stat();
        let mut begin_time = time::Instant::now();

        let speed_update_count = 0; // 速度统计点更新次数
        let report_span_count = REPORT_SPAN_MS / SPEED_SLOT_DURATION_MS; // 每隔多少个速度统计点上报一次

        loop {
            time::sleep(Duration::from_millis(SPEED_SLOT_DURATION_MS)).await;

            let tx = flow_stat.tx();
            let rx = flow_stat.rx();

            let now = time::Instant::now();
            let since_start_ms = if let Some(d) = now.checked_duration_since(begin_time) {
                d.as_millis() as u64
            } else {
                // 保护系统时间回退
                begin_time = now;
                0
            };
            
            let slot = (since_start_ms / SPEED_SLOT_DURATION_MS) as usize % SPEED_SLOT_COUNT;

            if slot != pre_slot {
                tx_slots[slot] = 0;
                rx_slots[slot] = 0;
                pre_slot = slot;
            }

            tx_slots[slot] += tx - pre_tx;
            rx_slots[slot] += rx - pre_rx;

            pre_tx = tx;
            pre_rx = rx;

            if speed_update_count % report_span_count == 0 {
                let speed_tx: u64 = tx_slots.iter().sum();
                let speed_rx: u64 = rx_slots.iter().sum();

                tracing::trace!(
                    "report: tx={} rx={} speed_tx={} speed_rx={}",
                    tx,
                    rx,
                    speed_tx,
                    speed_rx
                );
                let buf: [u64; 4] = [tx, rx, speed_tx, speed_rx];
                let buf = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const _, 32) };

                let _ = send_local_notify(&self.stat_addr, 1, buf).await;
            }
        }
    }
}

pub async fn send_local_notify(stat_addr: &LocalFlowStatAddress, cmd: u8, buf: &[u8]) -> io::Result<()> {
    use std::io::IoSlice;
    use tracing::debug;

    // Local flow statistic report RPC
    let timeout = Duration::from_secs(1);

    match stat_addr {
        #[cfg(unix)]
        LocalFlowStatAddress::UnixStreamPath(ref stat_path) => {
            use tokio::io::AsyncWriteExt;
            use tokio::net::UnixStream;

            let cmd = std::slice::from_ref(&cmd);
            // tracing::error!("xxxxx: xxxxxx cmd={:?}", cmd);
            let bufs: &[_] = &[IoSlice::new(&cmd), IoSlice::new(buf)];

            let mut stream = match time::timeout(timeout, UnixStream::connect(stat_path)).await {
                Ok(Ok(s)) => s,
                Ok(Err(err)) => {
                    tracing::error!(path = stat_path.to_str(), "send client flow statistic error: {}", err);
                    return Ok(());
                }
                Err(..) => {
                    debug!(path = stat_path.to_str(), "send client flow statistic error: timeout");
                    return Err(io::ErrorKind::TimedOut.into());
                }
            };

            match time::timeout(timeout, stream.write_vectored(bufs)).await {
                Ok(Ok(..)) => Ok(()),
                Ok(Err(err)) => {
                    debug!("send client flow statistic error: {}", err);
                    Err(err)
                }
                Err(..) => {
                    debug!("send client flow statistic error: timeout");
                    Err(io::ErrorKind::TimedOut.into())
                }
            }
        }
        LocalFlowStatAddress::TcpStreamAddr(stat_addr) => {
            use tokio::io::AsyncWriteExt;
            use tokio::net::TcpStream;

            let cmd = std::slice::from_ref(&cmd);
            // tracing::error!("xxxxx: xxxxxx cmd={:?}", cmd);
            let bufs: &[_] = &[IoSlice::new(&cmd), IoSlice::new(buf)];

            let mut stream = match time::timeout(timeout, TcpStream::connect(stat_addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(err)) => {
                    debug!("send client flow statistic error: {}", err);
                    return Err(err);
                }
                Err(..) => {
                    debug!("send client flow statistic error: timeout");
                    return Err(io::ErrorKind::TimedOut.into());
                }
            };

            match time::timeout(timeout, stream.write_vectored(bufs)).await {
                Ok(Ok(..)) => Ok(()),
                Ok(Err(err)) => {
                    debug!("send client flow statistic error: {}", err);
                    Err(err)
                }
                Err(..) => {
                    debug!("send client flow statistic error: timeout");
                    Err(io::ErrorKind::TimedOut.into())
                }
            }
        }
    }
}
