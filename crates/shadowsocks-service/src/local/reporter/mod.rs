use std::sync::Arc;
use std::{io, slice};

use tokio::time::{self, Duration};

use shadowsocks::canceler::CancelWaiter;

use crate::{
    config::LocalFlowStatAddress,
    local::{ServiceContext, StartStat},
};

pub struct ReporterServer {
    context: Arc<ServiceContext>,
    stat_addr: LocalFlowStatAddress,
    cancel_waiter: CancelWaiter,
}

impl ReporterServer {
    pub fn create(context: Arc<ServiceContext>, cancel_waiter: CancelWaiter, stat_addr: LocalFlowStatAddress) -> Self {
        Self {
            context,
            cancel_waiter,
            stat_addr,
        }
    }

    pub async fn run(self, start_stat: StartStat) -> io::Result<()> {
        let cancel_waiter = self.context.cancel_waiter();

        tokio::select! {
            _ = cancel_waiter.wait() => {
                return Ok(());
            }
            r = start_stat.wait() => {
                r?;
                send_local_notify(&self.stat_addr, 3, &[]).await?;
            }
        }

        // Local flow statistic report RPC
        let flow_stat = self.context.flow_stat();

        loop {
            // keep it as libev's default, 0.5 seconds
            tokio::select! {
                _ = cancel_waiter.wait() => {
                    return Ok(());
                }
                _ = time::sleep(Duration::from_millis(500)) => {
                }
                _ = self.cancel_waiter.wait() => {
                    tracing::trace!("canceled");
                    return Ok(());
                }
            }

            let tx = flow_stat.tx();
            let rx = flow_stat.rx();

            let buf: [u64; 2] = [tx, rx];
            let buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const _, 16) };

            let _ = send_local_notify(&self.stat_addr, 1, buf).await;
        }
    }
}

pub async fn send_local_notify(stat_addr: &LocalFlowStatAddress, cmd: u8, buf: &[u8]) -> io::Result<()> {
    use std::io::IoSlice;
    use tracing::debug;

    // Local flow statistic report RPC
    let timeout = Duration::from_secs(1);

    let cmd = std::slice::from_ref(&cmd);
    // tracing::error!("xxxxx: xxxxxx cmd={:?}", cmd);
    let bufs: &[_] = &[IoSlice::new(&cmd), IoSlice::new(buf)];

    match stat_addr {
        #[cfg(unix)]
        LocalFlowStatAddress::UnixStreamPath(ref stat_path) => {
            use tokio::io::AsyncWriteExt;
            use tokio::net::UnixStream;

            let mut stream = match time::timeout(timeout, UnixStream::connect(stat_path)).await {
                Ok(Ok(s)) => s,
                Ok(Err(err)) => {
                    debug!(path = stat_path.to_str(), "send client flow statistic error: {}", err);
                    return Err(err);
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
