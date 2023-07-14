use std::sync::Arc;
use std::{io, slice};

use tokio::time::{self, Duration};
use tracing::debug;

use shadowsocks::canceler::CancelWaiter;

use crate::{config::LocalFlowStatAddress, local::ServiceContext};

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

    pub async fn run(self) -> io::Result<()> {
        // Local flow statistic report RPC
        let timeout = Duration::from_secs(1);
        let flow_stat = self.context.flow_stat();

        loop {
            // keep it as libev's default, 0.5 seconds
            tokio::select! {
                _ = time::sleep(Duration::from_millis(500)) => {
                }
                _ = self.cancel_waiter.wait() => {
                    tracing::trace!("canceled");
                    return Ok(());
                }
            }
            time::sleep(Duration::from_millis(500)).await;

            let tx = flow_stat.tx();
            let rx = flow_stat.rx();

            let buf: [u64; 2] = [tx, rx];
            let buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const _, 16) };

            match self.stat_addr {
                #[cfg(unix)]
                LocalFlowStatAddress::UnixStreamPath(ref stat_path) => {
                    use tokio::io::AsyncWriteExt;
                    use tokio::net::UnixStream;

                    let mut stream = match time::timeout(timeout, UnixStream::connect(stat_path)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(err)) => {
                            debug!("send client flow statistic error: {}", err);
                            continue;
                        }
                        Err(..) => {
                            debug!("send client flow statistic error: timeout");
                            continue;
                        }
                    };

                    match time::timeout(timeout, stream.write_all(buf)).await {
                        Ok(Ok(..)) => {}
                        Ok(Err(err)) => {
                            debug!("send client flow statistic error: {}", err);
                        }
                        Err(..) => {
                            debug!("send client flow statistic error: timeout");
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
                            continue;
                        }
                        Err(..) => {
                            debug!("send client flow statistic error: timeout");
                            continue;
                        }
                    };

                    match time::timeout(timeout, stream.write_all(buf)).await {
                        Ok(Ok(..)) => {}
                        Ok(Err(err)) => {
                            debug!("send client flow statistic error: {}", err);
                        }
                        Err(..) => {
                            debug!("send client flow statistic error: timeout");
                        }
                    }
                }
            }
        }
    }
}
