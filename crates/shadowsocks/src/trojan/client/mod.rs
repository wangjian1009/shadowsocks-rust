use std::io;
use tokio::time;
use tracing::error;

use crate::{
    config::ServerConfig,
    net::{ConnectOpts, Destination},
    transport::{Connection, Connector, StreamConnection},
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
    let destination = Destination::Tcp(svr_cfg.external_addr().clone());

    let stream = match time::timeout(svr_cfg.timeout(), connector.connect(&destination, opts)).await {
        Ok(Ok(s)) => match s {
            Connection::Stream(s) => s,
            Connection::Packet { .. } => panic!(),
        },
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
