use super::*;

#[test]
fn tls_connector_parse_no_sni() {
    // assert_eq!(
    //     "tls://".parse::<TransportConnectorConfig>().unwrap(),
    //     TransportConnectorConfig::Tls(TlsConnectorConfig {
    //         sni: "www.google.com".to_owned(),
    //         cipher: vec![],
    //         cert: None,
    //     })
    // );
}

#[test]
fn tls_connector_parse_basic() {
    // assert_eq!(
    //     "tls://www.baidu.com/path/a?cipher=a&cipher=b&cert=/path/to/cert"
    //         .parse::<TransportConnectorConfig>()
    //         .unwrap(),
    //     TransportConnectorConfig::Tls(TlsConnectorConfig {
    //         sni: "www.baidu.com".to_owned(),
    //         cipher: vec!("a".to_string(), "b".to_string()),
    //         cert: Some("/path/to/cert".to_string()),
    //     })
    // );
}
