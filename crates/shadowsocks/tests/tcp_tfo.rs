#![cfg(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "freebsd"
))]

use byte_string::ByteStr;
use futures::future;
use shadowsocks::{
    config::{ServerProtocol, ServerType, ShadowsocksConfig},
    context::Context,
    crypto::CipherKind,
    net::{AcceptOpts, ConnectOpts},
    relay::{
        socks5::Address,
        tcprelay::utils::{copy_from_encrypted, copy_to_encrypted},
    },
    transport::direct::TcpConnector,
    ProxyClientStream, ProxyListener, ServerConfig,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tracing::debug;
use tracing_test::traced_test;

#[tokio::test]
#[traced_test]
async fn tcp_tunnel_tfo() {
    let svr_cfg = ServerConfig::new(
        ("127.0.0.1", 41000),
        ServerProtocol::SS(ShadowsocksConfig::new("?", CipherKind::NONE)),
    );
    let svr_cfg_client = svr_cfg.clone();

    tokio::spawn(async move {
        let context = Context::new_shared(ServerType::Server);

        let mut accept_opts = AcceptOpts::default();
        accept_opts.tcp.fastopen = true;

        let svr_ss_cfg = match svr_cfg.protocol() {
            ServerProtocol::SS(c) => c,
            _ => unreachable!(),
        };

        let listener = ProxyListener::bind_with_opts(context, &svr_cfg, svr_ss_cfg, accept_opts)
            .await
            .unwrap();

        while let Ok((mut stream, peer_addr)) = listener.accept().await {
            debug!("accepted {}", peer_addr);

            tokio::spawn(async move {
                let addr = stream.handshake().await.unwrap();
                let remote = match addr {
                    Address::SocketAddress(a) => TcpStream::connect(a).await.unwrap(),
                    Address::DomainNameAddress(name, port) => TcpStream::connect((name.as_str(), port)).await.unwrap(),
                };

                let (mut lr, mut lw) = tokio::io::split(stream);
                let (mut rr, mut rw) = remote.into_split();

                let l2r = copy_from_encrypted(CipherKind::NONE, &mut lr, &mut rw, None);
                let r2l = copy_to_encrypted(CipherKind::NONE, &mut rr, &mut lw, None);

                tokio::pin!(l2r);
                tokio::pin!(r2l);

                let _ = future::select(l2r, r2l).await;
            });
        }
    });

    tokio::task::yield_now().await;

    let context = Context::new_shared(ServerType::Local);
    let connector = TcpConnector::new(Some(context.clone()));

    let mut connect_opts = ConnectOpts::default();
    connect_opts.tcp.fastopen = true;

    let mut client = ProxyClientStream::connect_with_opts(
        context,
        &connector,
        &svr_cfg_client,
        if let ServerProtocol::SS(c) = svr_cfg_client.protocol() {
            c
        } else {
            unreachable!();
        },
        ("www.example.com".to_owned(), 80).into(),
        &connect_opts,
    )
    .await
    .unwrap();

    client
        .write_all(b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(client);

    let mut buffer = Vec::new();
    reader.read_until(b'\n', &mut buffer).await.unwrap();

    println!("{:?}", ByteStr::new(&buffer));

    static HTTP_RESPONSE_STATUS: &[u8] = b"HTTP/1.0 200 OK\r\n";
    assert!(buffer.starts_with(HTTP_RESPONSE_STATUS));
}
