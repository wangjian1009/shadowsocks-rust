use super::*;

#[test]
fn wss_acceptor_basic() {
    // assert_eq!(
    //     "wss://www.baidu.com/path/a?cipher=a&cipher=b&cert=/path/to/cert&key=/path/to/key"
    //         .parse::<TransportAcceptorConfig>()
    //         .unwrap(),
    //     TransportAcceptorConfig::Wss(
    //         WebSocketAcceptorConfig {
    //             path: "/path/a".to_owned(),
    //         },
    //         TlsAcceptorConfig {
    //             cert: "/path/to/cert".to_string(),
    //             key: "/path/to/key".to_string(),
    //             cipher: vec!("a".to_string(), "b".to_string()),
    //         },
    //     )
    // );
}

#[test]
fn wss_connector_basic() {
    // assert_eq!(
    //     "wss://www.baidu.com/path/a?cipher=a&cipher=b&cert=/path/to/cert&key=/path/to/key"
    //         .parse::<TransportConnectorConfig>()
    //         .unwrap(),
    //     TransportConnectorConfig::Wss(
    //         WebSocketConnectorConfig {
    //             path: "/path/a".to_owned(),
    //             host: "www.baidu.com".to_owned(),
    //         },
    //         TlsConnectorConfig {
    //             sni: "www.baidu.com".to_owned(),
    //             cipher: vec!("a".to_string(), "b".to_string()),
    //             cert: Some("/path/to/cert".to_string()),
    //         },
    //     )
    // );
}
