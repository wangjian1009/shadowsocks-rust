#![cfg(all(feature = "local", feature = "server"))]

use std::net::{SocketAddr, ToSocketAddrs};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    time::{self, Duration},
};

use shadowsocks_service::{
    config::{Config, ConfigType, LocalConfig, ProtocolType},
    local::socks::client::socks5::{Socks5TcpClient, Socks5UdpClient},
    run_local, run_server,
    shadowsocks::{
        config::{Mode, ServerAddr, ServerConfig, ServerProtocol, ShadowsocksConfig},
        crypto::CipherKind,
        net::util::generate_port,
        relay::socks5::Address,
    },
};

#[cfg(feature = "transport")]
use shadowsocks_service::shadowsocks::config::{TransportAcceptorConfig, TransportConnectorConfig};

#[cfg(feature = "transport-ws")]
use shadowsocks_service::shadowsocks::transport::websocket;

#[cfg(feature = "transport-tls")]
use shadowsocks_service::shadowsocks::transport::tls;

#[cfg(feature = "transport-skcp")]
use shadowsocks_service::shadowsocks::transport::skcp;

#[cfg(feature = "trojan")]
use shadowsocks_service::shadowsocks::config::TrojanConfig;

#[cfg(feature = "vless")]
use shadowsocks_service::shadowsocks::config::VlessConfig;

pub struct Socks5TestServer {
    local_addr: SocketAddr,
    svr_config: Config,
    cli_config: Config,
}

impl Socks5TestServer {
    pub fn new<S, L>(
        svr_addr: S,
        local_addr: L,
        p: ServerProtocol,
        #[cfg(feature = "transport")] ts: Option<TransportAcceptorConfig>,
        #[cfg(feature = "transport")] tc: Option<TransportConnectorConfig>,
        mode: Mode,
    ) -> Socks5TestServer
    where
        S: ToSocketAddrs,
        L: ToSocketAddrs,
    {
        let svr_addr = svr_addr.to_socket_addrs().unwrap().next().unwrap();
        let local_addr = local_addr.to_socket_addrs().unwrap().next().unwrap();

        let p2 = p.clone();
        Socks5TestServer {
            local_addr,
            svr_config: {
                let mut cfg = Config::new(ConfigType::Server);
                cfg.server = vec![ServerConfig::new(svr_addr, p)];
                cfg.server[0].set_mode(mode);
                #[cfg(feature = "transport")]
                cfg.server[0].set_acceptor_transport(ts);
                cfg
            },
            cli_config: {
                let mut cfg = Config::new(ConfigType::Local);
                cfg.local = vec![LocalConfig::new_with_addr(
                    ServerAddr::from(local_addr),
                    ProtocolType::Socks,
                )];
                cfg.local[0].mode = mode;
                cfg.server = vec![ServerConfig::new(svr_addr, p2)];
                #[cfg(feature = "transport")]
                cfg.server[0].set_connector_transport(tc);
                cfg
            },
        }
    }

    pub fn client_addr(&self) -> &SocketAddr {
        &self.local_addr
    }

    pub async fn run(&self) {
        let svr_cfg = self.svr_config.clone();
        tokio::spawn(run_server(svr_cfg));

        let client_cfg = self.cli_config.clone();
        tokio::spawn(run_local(client_cfg));

        time::sleep(Duration::from_secs(1)).await;
    }
}

async fn socks5_tcp_relay_test(
    p: ServerProtocol,
    #[cfg(feature = "transport")] ts: Option<TransportAcceptorConfig>,
    #[cfg(feature = "transport")] tc: Option<TransportConnectorConfig>,
) {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init();

    let svr = Socks5TestServer::new(
        format!("127.0.0.1:{}", generate_port().expect("generate port error")),
        format!("127.0.0.1:{}", generate_port().expect("generate port error")),
        p,
        #[cfg(feature = "transport")]
        ts,
        #[cfg(feature = "transport")]
        tc,
        Mode::TcpOnly,
    );
    svr.run().await;

    let mut c = Socks5TcpClient::connect(
        Address::DomainNameAddress("www.example.com".to_owned(), 80),
        svr.client_addr(),
    )
    .await
    .unwrap();

    let req = b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n";
    c.write_all(req).await.unwrap();
    c.flush().await.unwrap();

    let mut r = BufReader::new(c);

    let mut buf = Vec::new();
    r.read_until(b'\n', &mut buf).await.unwrap();

    let http_status = b"HTTP/1.0 200 OK\r\n";
    assert!(buf.starts_with(http_status));
}

fn start_udp_echo_server(port: u16) -> String {
    use tokio::net::UdpSocket;

    let udp_echo_server_addr = format!("127.0.0.1:{}", port);
    let dup_addr = udp_echo_server_addr.clone();

    tokio::spawn(async move {
        let l = UdpSocket::bind(dup_addr.clone()).await.unwrap();

        log::debug!("UDP echo server started {}", dup_addr);

        let mut buf = vec![0u8; 65536];
        let (amt, src) = l.recv_from(&mut buf).await.unwrap();

        log::debug!("UDP echo received {} bytes from {}", amt, src);

        l.send_to(&buf[..amt], &src).await.unwrap();

        log::debug!("UDP echo sent {} bytes to {}", amt, src);
    });

    udp_echo_server_addr
}

async fn socks5_udp_relay_test(
    p: ServerProtocol,
    #[cfg(feature = "transport")] ts: Option<TransportAcceptorConfig>,
    #[cfg(feature = "transport")] tc: Option<TransportConnectorConfig>,
) {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init();

    let remote_echo_addr = start_udp_echo_server(generate_port().expect("generate port error"))
        .parse::<Address>()
        .unwrap();
    let socks_remote_addr = format!("127.0.0.1:{}", generate_port().expect("generate port error"));
    let socks_local_addr = format!("127.0.0.1:{}", generate_port().expect("generate port error"));

    let svr = Socks5TestServer::new(
        socks_remote_addr,
        socks_local_addr.clone(),
        p,
        #[cfg(feature = "transport")]
        ts,
        #[cfg(feature = "transport")]
        tc,
        Mode::TcpAndUdp,
    );
    svr.run().await;

    let mut l = Socks5UdpClient::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    l.associate(&socks_local_addr).await.unwrap();

    let payload = b"HEllo WORld";
    l.send_to(0, payload, &remote_echo_addr).await.unwrap();

    let mut buf = vec![0u8; 65536];
    let (amt, _, recv_addr) = time::timeout(Duration::from_secs(5), l.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    println!("Received {} buf size={} {:?}", recv_addr, amt, &buf[..amt]);

    assert_eq!(recv_addr, remote_echo_addr);
    assert_eq!(&buf[..amt], payload);
}

#[tokio::test]
async fn socks5_udp_relay_ss() {
    socks5_udp_relay_test(
        ServerProtocol::SS(ShadowsocksConfig::new("test-password", CipherKind::AES_128_GCM)),
        #[cfg(feature = "transport")]
        None,
        #[cfg(feature = "transport")]
        None,
    )
    .await
}

#[cfg(feature = "stream-cipher")]
#[tokio::test]
async fn socks5_tcp_relay_ss_stream() {
    socks5_tcp_relay_test(
        ServerProtocol::SS(ShadowsocksConfig::new("test-password", CipherKind::AES_128_CFB128)),
        #[cfg(feature = "transport")]
        None,
        #[cfg(feature = "transport")]
        None,
    )
    .await
}

#[tokio::test]
async fn socks5_tcp_relay_ss_aead() {
    socks5_tcp_relay_test(
        ServerProtocol::SS(ShadowsocksConfig::new("test-password", CipherKind::AES_256_GCM)),
        #[cfg(feature = "transport")]
        None,
        #[cfg(feature = "transport")]
        None,
    )
    .await
}

#[cfg(feature = "transport-ws")]
#[tokio::test]
async fn socks5_udp_relay_ss_ws() {
    socks5_udp_relay_test(
        ServerProtocol::SS(ShadowsocksConfig::new("test-password", CipherKind::AES_128_GCM)),
        Some(TransportAcceptorConfig::Ws(websocket::WebSocketAcceptorConfig {
            path: "/a".to_owned(),
        })),
        Some(TransportConnectorConfig::Ws(websocket::WebSocketConnectorConfig {
            path: "/a".to_owned(),
            host: "www.google.com".to_owned(),
        })),
    )
    .await
}

#[cfg(feature = "transport-ws")]
#[tokio::test]
async fn socks5_tcp_relay_ss_ws() {
    use shadowsocks_service::shadowsocks::transport::websocket;

    socks5_tcp_relay_test(
        ServerProtocol::SS(ShadowsocksConfig::new("test-password", CipherKind::AES_256_GCM)),
        Some(TransportAcceptorConfig::Ws(websocket::WebSocketAcceptorConfig {
            path: "/a".to_owned(),
        })),
        Some(TransportConnectorConfig::Ws(websocket::WebSocketConnectorConfig {
            path: "/a".to_owned(),
            host: "www.google.com".to_owned(),
        })),
    )
    .await
}

#[cfg(feature = "transport-tls")]
#[tokio::test]
async fn socks5_tcp_relay_ss_tls() {
    socks5_tcp_relay_test(
        ServerProtocol::SS(ShadowsocksConfig::new("test-password", CipherKind::AES_256_GCM)),
        Some(TransportAcceptorConfig::Tls(tls::TlsAcceptorConfig {
            cert: "tests/cert/server.crt".to_owned(),
            key: "tests/cert/server.key".to_owned(),
            cipher: None,
        })),
        Some(TransportConnectorConfig::Tls(tls::TlsConnectorConfig {
            sni: "www.google.com".to_owned(),
            cert: None,
            cipher: None,
        })),
    )
    .await
}

#[cfg(all(feature = "transport-tls", feature = "transport-ws"))]
#[tokio::test]
async fn socks5_tcp_relay_ss_wss() {
    socks5_tcp_relay_test(
        ServerProtocol::SS(ShadowsocksConfig::new("test-password", CipherKind::AES_256_GCM)),
        Some(TransportAcceptorConfig::Wss(
            websocket::WebSocketAcceptorConfig { path: "/a".to_owned() },
            tls::TlsAcceptorConfig {
                cert: "tests/cert/server.crt".to_owned(),
                key: "tests/cert/server.key".to_owned(),
                cipher: None,
            },
        )),
        Some(TransportConnectorConfig::Wss(
            websocket::WebSocketConnectorConfig {
                path: "/a".to_owned(),
                host: "www.google.com".to_owned(),
            },
            tls::TlsConnectorConfig {
                sni: "www.google.com".to_owned(),
                cert: None,
                cipher: None,
            },
        )),
    )
    .await
}

#[cfg(feature = "transport-skcp")]
#[tokio::test]
async fn socks5_tcp_relay_ss_skcp() {
    socks5_tcp_relay_test(
        ServerProtocol::SS(ShadowsocksConfig::new("test-password", CipherKind::AES_256_GCM)),
        Some(TransportAcceptorConfig::Skcp(skcp::SkcpConfig::default())),
        Some(TransportConnectorConfig::Skcp(skcp::SkcpConfig::default())),
    )
    .await
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn socks5_tcp_relay_trojan() {
    socks5_tcp_relay_test(
        ServerProtocol::Trojan(TrojanConfig::new("test-password")),
        #[cfg(feature = "transport")]
        None,
        #[cfg(feature = "transport")]
        None,
    )
    .await
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn socks5_udp_relay_trojan() {
    socks5_udp_relay_test(
        ServerProtocol::Trojan(TrojanConfig::new("test-password")),
        #[cfg(feature = "transport")]
        None,
        #[cfg(feature = "transport")]
        None,
    )
    .await
}

#[cfg(feature = "vless")]
#[tokio::test]
async fn socks5_tcp_relay_vless() {
    let mut config = VlessConfig::new();
    config
        .add_user(0, "66ad4540-b58c-4ad2-9926-ea63445a9b57", None)
        .unwrap();

    socks5_tcp_relay_test(
        ServerProtocol::Vless(config),
        #[cfg(feature = "transport")]
        None,
        #[cfg(feature = "transport")]
        None,
    )
    .await
}

#[cfg(feature = "vless")]
#[tokio::test]
async fn socks5_udp_relay_vless() {
    let mut config = VlessConfig::new();
    config
        .add_user(0, "66ad4540-b58c-4ad2-9926-ea63445a9b57", None)
        .unwrap();

    socks5_udp_relay_test(
        ServerProtocol::Vless(config),
        #[cfg(feature = "transport")]
        None,
        #[cfg(feature = "transport")]
        None,
    )
    .await
}

#[cfg(all(feature = "vless", feature = "transport-skcp"))]
#[tokio::test]
async fn socks5_tcp_relay_vless_skcp() {
    let mut config = VlessConfig::new();
    config
        .add_user(0, "66ad4540-b58c-4ad2-9926-ea63445a9b57", None)
        .unwrap();

    socks5_tcp_relay_test(
        ServerProtocol::Vless(config),
        Some(TransportAcceptorConfig::Skcp(skcp::SkcpConfig::default())),
        Some(TransportConnectorConfig::Skcp(skcp::SkcpConfig::default())),
    )
    .await
}

#[cfg(all(feature = "vless", feature = "transport-skcp"))]
#[tokio::test]
async fn socks5_udp_relay_vless_skcp() {
    let mut config = VlessConfig::new();
    config
        .add_user(0, "66ad4540-b58c-4ad2-9926-ea63445a9b57", None)
        .unwrap();

    socks5_udp_relay_test(
        ServerProtocol::Vless(config),
        Some(TransportAcceptorConfig::Skcp(skcp::SkcpConfig::default())),
        Some(TransportConnectorConfig::Skcp(skcp::SkcpConfig::default())),
    )
    .await
}
