use super::super::*;

#[cfg(feature = "transport-ws")]
use crate::transport::websocket::WebSocketConnectorConfig;

#[cfg(feature = "transport-tls")]
use crate::transport::tls::TlsConnectorConfig;

#[cfg(any(feature = "transport-mkcp", feature = "transport-skcp"))]
use crate::transport::HeaderConfig;

#[cfg(feature = "transport-mkcp")]
use crate::transport::mkcp::MkcpConfig;

#[cfg(feature = "transport-skcp")]
use crate::transport::skcp::SkcpConfig;

#[test]
fn rebuild_ss() {
    let config = ServerConfig::new(
        "1.2.3.4:5".parse::<ServerAddr>().unwrap(),
        ServerProtocol::SS(ShadowsocksConfig::new("pwd1", CipherKind::AES_128_GCM)),
    );

    let url = config.to_url();

    let config_rebuild = url.parse::<ServerConfig>().unwrap();

    assert_eq!(config, config_rebuild);
}

#[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
#[test]
#[traced_test]
fn parse_vless_wss() {
    let parsed_config = "vless://9af5ce16-8020-4530-85ba-290ef2290d1c@194.233.85.194:443/?type=ws&encryption=none&path=%2Feaps2021sg&security=tls&sni=proxy0101.com#194-test".parse::<ServerConfig>().unwrap();

    let mut vless_config = VlessConfig::new();
    vless_config
        .add_user(0, "9af5ce16-8020-4530-85ba-290ef2290d1c", None)
        .unwrap();

    let mut expect_config = ServerConfig::new(
        "194.233.85.194:443".parse::<ServerAddr>().unwrap(),
        ServerProtocol::Vless(vless_config),
    );

    expect_config.set_remarks("194-test");

    expect_config.set_connector_transport(Some(TransportConnectorConfig::Wss(
        WebSocketConnectorConfig {
            path: "/eaps2021sg".to_owned(),
            host: crate::config::transport::DEFAULT_SNI.to_owned(),
        },
        TlsConnectorConfig {
            sni: "proxy0101.com".to_owned(),
            cipher: vec![],
            cert: None,
        },
    )));

    assert_eq!(parsed_config, expect_config);
}

#[cfg(feature = "transport-mkcp")]
#[test]
#[traced_test]
fn parse_vless_mkcp() {
    let parsed_config = "vless://c93b0258-6847-42c8-92ac-7b8ac8e390ad@104.237.56.68:7777/?type=kcp&encryption=none&headerType=wechat-video&seed=itest123#68-us".parse::<ServerConfig>().unwrap();

    let mut vless_config = VlessConfig::new();
    vless_config
        .add_user(0, "c93b0258-6847-42c8-92ac-7b8ac8e390ad", None)
        .unwrap();

    let mut expect_config = ServerConfig::new(
        "104.237.56.68:7777".parse::<ServerAddr>().unwrap(),
        ServerProtocol::Vless(vless_config),
    );

    expect_config.set_remarks("68-us");

    let mut mkcp_config = MkcpConfig::default();
    mkcp_config.header_config = Some(HeaderConfig::Wechat);
    mkcp_config.seed = Some("itest123".to_owned());
    expect_config.set_connector_transport(Some(TransportConnectorConfig::Mkcp(mkcp_config)));

    assert_eq!(parsed_config, expect_config);
}

#[cfg(feature = "transport-skcp")]
#[test]
#[traced_test]
fn parse_vless_skcp() {
    let parsed_config =
        "vless://c93b0258-6847-42c8-92ac-7b8ac8e390ad@104.237.56.68:7777/?type=skcp&header=wechat-video#68-us"
            .parse::<ServerConfig>()
            .unwrap();

    let mut vless_config = VlessConfig::new();
    vless_config
        .add_user(0, "c93b0258-6847-42c8-92ac-7b8ac8e390ad", None)
        .unwrap();

    let mut expect_config = ServerConfig::new(
        "104.237.56.68:7777".parse::<ServerAddr>().unwrap(),
        ServerProtocol::Vless(vless_config),
    );

    expect_config.set_remarks("68-us");

    let mut skcp_config = SkcpConfig::default();
    skcp_config.header_config = Some(HeaderConfig::Wechat);
    expect_config.set_connector_transport(Some(TransportConnectorConfig::Skcp(skcp_config)));

    assert_eq!(parsed_config, expect_config);
}

#[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
#[test]
fn rebuild_vless_wss() {
    let mut vless_config = VlessConfig::new();
    vless_config
        .add_user(0, "9af5ce16-8020-4530-85ba-290ef2290d1c", None)
        .unwrap();

    let mut config = ServerConfig::new(
        "1.2.3.4:5".parse::<ServerAddr>().unwrap(),
        ServerProtocol::Vless(vless_config),
    );

    config.set_connector_transport(Some(TransportConnectorConfig::Wss(
        WebSocketConnectorConfig {
            path: "/eaps2021sg".to_owned(),
            host: crate::config::transport::DEFAULT_SNI.to_owned(),
        },
        TlsConnectorConfig {
            sni: "proxy0101.com".to_owned(),
            cipher: vec![],
            cert: None,
        },
    )));

    let url = config.to_url();

    let config_rebuild = url.parse::<ServerConfig>().unwrap();

    assert_eq!(config, config_rebuild);
}
