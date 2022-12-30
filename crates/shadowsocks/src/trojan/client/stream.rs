use std::io;

use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

use crate::{
    config::ServerConfig,
    net::ConnectOpts,
    transport::{Connector, StreamConnection},
    ServerAddr,
};

use super::super::{
    packet::{new_trojan_packet_connection, TrojanUdpReader, TrojanUdpWriter},
    protocol::{Address, RequestHeader},
    Config,
};

pub async fn connect_stream<C, S, F>(
    connector: &C,
    svr_cfg: &ServerConfig,
    svr_trojan_cfg: &Config,
    addr: ServerAddr,
    opts: &ConnectOpts,
    map_fn: F,
) -> io::Result<S>
where
    C: Connector,
    S: StreamConnection,
    F: FnOnce(C::TS) -> S,
{
    let mut stream = super::connect(connector, svr_cfg, opts, map_fn).await?;

    let request = RequestHeader::TcpConnect(svr_trojan_cfg.hash(), Address::from(addr));

    let request_length = request.serialized_len();
    let mut buffer = BytesMut::with_capacity(request_length);
    request.write_to_buf(&mut buffer);

    let _ = stream.write(&buffer).await?;

    Ok(stream)
}

pub async fn connect_packet<C, S, F>(
    connector: &C,
    svr_cfg: &ServerConfig,
    svr_trojan_cfg: &Config,
    opts: &ConnectOpts,
    map_fn: F,
) -> io::Result<(TrojanUdpReader<S>, TrojanUdpWriter<S>)>
where
    C: Connector,
    S: StreamConnection,
    F: FnOnce(C::TS) -> S,
{
    let mut stream = super::connect(connector, svr_cfg, opts, map_fn).await?;

    let request = RequestHeader::UdpAssociate(svr_trojan_cfg.hash());

    let request_length = request.serialized_len();
    let mut buffer = BytesMut::with_capacity(request_length);
    request.write_to_buf(&mut buffer);

    let _ = stream.write(&buffer).await?;

    Ok(new_trojan_packet_connection(stream))
}
