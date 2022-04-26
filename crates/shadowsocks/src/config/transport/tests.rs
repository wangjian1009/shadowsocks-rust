use super::*;

#[test]
fn not_support_protocol() {
    assert_eq!(
        format!("{:?}", "not-support://".parse::<TransportConnectorConfig>()),
        "Err(\"not support transport protocol not-support\")",
    );
}

#[cfg(feature = "transport-ws")]
mod ws_connector;

#[cfg(feature = "transport-tls")]
mod tls_connector;

#[cfg(feature = "transport-tls")]
mod tls_acceptor;

#[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
mod wss;

#[cfg(feature = "transport-skcp")]
mod skcp;
