use super::*;

#[test]
fn ws_connector_parse_empty() {
    assert_eq!(
        "ws://".parse::<TransportConnectorConfig>().unwrap(),
        TransportConnectorConfig::Ws(WebSocketConnectorConfig {
            uri: format!("ws://{}", DEFAULT_SNI).parse().unwrap(),
            ..Default::default()
        })
    );
}

#[test]
fn ws_connector_parse_path_only() {
    assert_eq!(
        "ws://path/a".parse::<TransportConnectorConfig>().unwrap(),
        TransportConnectorConfig::Ws(WebSocketConnectorConfig {
            uri: format!("ws://{}/path/a", DEFAULT_SNI).parse().unwrap(),
            ..Default::default()
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
            uri: format!("ws://www.baidu.com/path/a").parse().unwrap(),
            ..Default::default()
        })
    );
}

#[test]
fn ws_connector_to_str() {
    assert_eq!(
        format!(
            "{}",
            TransportConnectorConfig::Ws(WebSocketConnectorConfig {
                uri: format!("ws://").parse().unwrap(),
                ..Default::default()
            })
        )
        .as_str(),
        "ws://",
    );

    assert_eq!(
        format!(
            "{}",
            TransportConnectorConfig::Ws(WebSocketConnectorConfig {
                uri: format!("ws://").parse().unwrap(),
                ..Default::default()
            })
        )
        .as_str(),
        "ws://",
    );

    assert_eq!(
        format!(
            "{}",
            TransportConnectorConfig::Ws(WebSocketConnectorConfig {
                uri: format!("ws://path/a").parse().unwrap(),
                ..Default::default()
            })
        )
        .as_str(),
        "ws://path/a",
    );
}
