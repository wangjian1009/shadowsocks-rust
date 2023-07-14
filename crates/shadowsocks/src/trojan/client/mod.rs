use std::io;
use tokio::time;
use tracing::error;

use crate::{
    config::ServerConfig,
    net::ConnectOpts,
    transport::{Connector, StreamConnection},
};

mod delay_connect_stream;
pub use delay_connect_stream::DelayConnectStream;

mod stream;
pub use stream::{connect_packet, connect_stream};

async fn connect<C, S, F>(connector: &C, svr_cfg: &ServerConfig, opts: &ConnectOpts, map_fn: F) -> io::Result<S>
where
    C: Connector,
    S: StreamConnection,
    F: FnOnce(C::TS) -> S,
{
    let stream = match time::timeout(svr_cfg.timeout(), connector.connect(svr_cfg.tcp_external_addr(), opts)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            error!(error = ?e, "connect error");
            return Err(e);
        }
        Err(e) => {
            error!(error = ?e, "connect timeout");
            return Err(io::ErrorKind::TimedOut.into());
        }
    };

    Ok(map_fn(stream))
}
