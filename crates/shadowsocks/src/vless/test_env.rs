use tokio::io;

use super::{protocol, Address, ClientStream, UUID};
use crate::net::TcpStream;

// 测试环境需要搭建，通过连接真实的服务器进行测试
const EXTERNAL_SVR_ADDR: &'static str = "127.0.0.1:443";
const EXTERNAL_USER_ID: &'static str = "6f923f30-1d80-49e4-b350-bb9b0512a09b";

pub async fn connect_external_direct(
    command: protocol::RequestCommand,
    target_addr: &str,
) -> io::Result<ClientStream<TcpStream>> {
    let svr_addr = EXTERNAL_SVR_ADDR.parse::<std::net::SocketAddr>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("parse svr address {EXTERNAL_SVR_ADDR} error {e}"),
        )
    })?;

    let stream = TcpStream::connect_with_opts(&svr_addr, &Default::default())
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("parse svr address {svr_addr} error {e}")))?;

    let user_id = EXTERNAL_USER_ID.parse::<UUID>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("parse user id {EXTERNAL_USER_ID} error {e}"),
        )
    })?;

    let target_addr = target_addr
        .parse::<Address>()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("target addr {target_addr} error {e}")))?;

    Ok(ClientStream::new(
        stream,
        user_id,
        command,
        target_addr,
    ))
}
