use super::super::*;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::task::JoinHandle;

use crate::{
    net::{ConnectOpts, UdpSocket},
    transport::{direct::TcpConnector, Acceptor, Connector},
    ServerAddr,
};

type TestMkcpAcceptor = MkcpAcceptor;
type TestMkcpConnector = MkcpConnector;
type TestMkcpClientStream = <TestMkcpConnector as Connector>::TS;

pub async fn create_acceptor(
    config: Arc<MkcpConfig>,
    port: u16,
    statistic: Option<Arc<StatisticStat>>,
) -> TestMkcpAcceptor {
    // 创建服务
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    let socket = UdpSocket::listen(&listen_addr)
        .await
        .unwrap_or_else(|err| panic!("启动监听服务数据 {}", err));

    let r = Arc::new(socket);
    let w = r.clone();
    let local_addr = r.local_addr().unwrap();
    TestMkcpAcceptor::new(config, local_addr, r, w, statistic)
}

pub fn start_echo_server(mut listener: TestMkcpAcceptor) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((stream, _peer_addr)) = listener.accept().await {
            let (mut r, mut w) = tokio::io::split(stream);

            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut r, &mut w).await;
                tracing::debug!("服务端数据传输任务退出");
            });
        }
    })
}

pub async fn connect_to(
    config: Arc<MkcpConfig>,
    port: u16,
    statistic: Option<Arc<StatisticStat>>,
) -> io::Result<TestMkcpClientStream> {
    // 客户端连接
    let connector = TcpConnector::new(None);
    let connector = MkcpConnector::new(config, statistic);

    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    let conn = connector
        .connect(&ServerAddr::SocketAddr(listen_addr), &ConnectOpts::default())
        .await?;

    Ok(conn)
}
