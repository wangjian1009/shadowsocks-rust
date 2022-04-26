use std::time::Duration;

use super::*;
use crate::transport::skcp::KcpNoDelayConfig;

#[test]
fn skcp_default() {
    assert_eq!(
        "skcp://".parse::<TransportAcceptorConfig>().unwrap(),
        TransportAcceptorConfig::Skcp(SkcpConfig::default())
    );
}

#[test]
fn skcp_mode_default() {
    assert_eq!(
        "skcp://?mode=default".parse::<TransportAcceptorConfig>().unwrap(),
        TransportAcceptorConfig::Skcp(SkcpConfig::default())
    );
}

#[test]
fn skcp_mode_fastest() {
    assert_eq!(
        "skcp://?mode=fastest".parse::<TransportAcceptorConfig>().unwrap(),
        TransportAcceptorConfig::Skcp(SkcpConfig {
            nodelay: KcpNoDelayConfig::fastest(),
            ..SkcpConfig::default()
        })
    );
}

#[test]
fn skcp_mode_normal() {
    assert_eq!(
        "skcp://?mode=normal".parse::<TransportAcceptorConfig>().unwrap(),
        TransportAcceptorConfig::Skcp(SkcpConfig {
            nodelay: KcpNoDelayConfig::normal(),
            ..SkcpConfig::default()
        })
    );
}

#[test]
fn skcp_connector_basic() {
    assert_eq!(
        "skcp://?mode=normal&mtu=100&nodelay=true&interval=101&resend=1&nc=true&wnd-size-send=3&wnd-size-recv=4&session-expire=40&flush-write=true&flush-acks-input=true&stream=false"
            .parse::<TransportAcceptorConfig>()
            .unwrap(),
        TransportAcceptorConfig::Skcp(SkcpConfig {
            mtu: 100,
            nodelay: KcpNoDelayConfig {
                nodelay: true,
                interval: 101,
                resend: 1,
                nc: true,
            },
            wnd_size: (3, 4),
            session_expire: Duration::from_secs(40),
            flush_write: true,
            flush_acks_input: true,
            stream: false,
        },)
    );
}

#[test]
fn skcp_connector_rebuild() {
    let expect = TransportAcceptorConfig::Skcp(SkcpConfig {
        mtu: 100,
        nodelay: KcpNoDelayConfig {
            nodelay: true,
            interval: 101,
            resend: 1,
            nc: true,
        },
        wnd_size: (3, 4),
        session_expire: Duration::from_secs(40),
        flush_write: true,
        flush_acks_input: true,
        stream: false,
    });

    assert_eq!(expect.to_string().parse::<TransportAcceptorConfig>().unwrap(), expect);
}
