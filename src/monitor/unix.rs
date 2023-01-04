use futures::future::{self, Either, FutureExt};
use shadowsocks_service::shadowsocks::canceler::Canceler;
use std::{io, sync::Arc};
use tokio::{
    signal::unix::{signal, SignalKind},
    time::{self, Duration, Instant},
};
use tracing::{error, info};

/// Create a monitor future for signals
///
/// It will exit when received `SIGTERM` or `SIGINT`.
pub async fn create_signal_monitor(canceler: Arc<Canceler>) -> io::Result<()> {
    // Future resolving to two signal streams. Can fail if setting up signal monitoring fails
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut expire_time = None;

    loop {
        tokio::select! {
            r = future::select(sigterm.recv().boxed(), sigint.recv().boxed()) => {
                let signal_name = match r {
                    Either::Left(..) => "SIGTERM",
                    Either::Right(..) => "SIGINT",
                };

                if canceler.is_canceled() {
                    info!("received {}, force exiting", signal_name);
                    break;
                } else {
                    info!("received {}, soft exiting", signal_name);
                    expire_time = Instant::now().checked_add(Duration::from_secs(1));
                    canceler.cancel();
                }
            }
            _ = wait_timeout(&expire_time) => {
                error!("soft exiting timeout, force exiting");
                break;
            }
        }
    }

    Ok(())
}

async fn wait_timeout(expire_time: &Option<Instant>) {
    match expire_time {
        Some(expire_time) => time::sleep_until(*expire_time).await,
        None => future::pending().await,
    }
}
