use super::*;

#[test]
fn ws_connector_parse_empty() {
    assert_eq!(
        "ws://".parse::<TransportConnectorConfig>().unwrap(),
        TransportConnectorConfig::Ws(WebSocketConnectorConfig {
            path: "/".to_owned(),
            host: DEFAULT_SNI.to_owned(),
        })
    );
}

#[test]
fn ws_connector_parse_path_only() {
    assert_eq!(
        "ws://path/a".parse::<TransportConnectorConfig>().unwrap(),
        TransportConnectorConfig::Ws(WebSocketConnectorConfig {
            path: "/path/a".to_owned(),
            host: DEFAULT_SNI.to_owned(),
        })
    );
}

#[test]
fn ws_connector_parse_full() {
    assert_eq!(
        "ws://www.baidu.com/path/a?a=av&b=bv"
            .parse::<TransportConnectorConfig>()
            .unwrap(),
        TransportConnectorConfig::Ws(WebSocketConnectorConfig {
            path: "/path/a".to_owned(),
            host: "www.baidu.com".to_owned(),
        })
    );
}

#[test]
fn ws_connector_to_str() {
    assert_eq!(
        format!(
            "{}",
            TransportConnectorConfig::Ws(WebSocketConnectorConfig {
                path: "/".to_owned(),
                host: DEFAULT_SNI.to_owned(),
            })
        )
        .as_str(),
        "ws://",
    );

    assert_eq!(
        format!(
            "{}",
            TransportConnectorConfig::Ws(WebSocketConnectorConfig {
                path: "".to_owned(),
                host: DEFAULT_SNI.to_owned(),
            })
        )
        .as_str(),
        "ws://",
    );

    assert_eq!(
        format!(
            "{}",
            TransportConnectorConfig::Ws(WebSocketConnectorConfig {
                path: "/path/a".to_owned(),
                host: DEFAULT_SNI.to_owned(),
            })
        )
        .as_str(),
        "ws://path/a",
    );
}
