use super::*;

#[test]
fn tls_acceptor_parse_basic() {
    // assert_eq!(
    //     "tls://www.baidu.com/path/a?cipher=a&cipher=b&cert=/path/to/cert&key=/path/to/key"
    //         .parse::<TransportAcceptorConfig>()
    //         .unwrap(),
    //     TransportAcceptorConfig::Tls(TlsAcceptorConfig {
    //         cert: "/path/to/cert".to_string(),
    //         key: "/path/to/key".to_string(),
    //         cipher: Some(vec!("a".to_string(), "b".to_string())),
    //     })
    // );
}

#[test]
fn tls_acceptor_parse_no_key() {
    assert_eq!(
        format!(
            "{:?}",
            "tls://www.baidu.com/path/a?cipher=a&cipher=b&cert=/path/to/cert".parse::<TransportAcceptorConfig>()
        ),
        "Err(\"transport tls key not configured\")"
    );
}

#[test]
fn tls_acceptor_parse_no_cert() {
    assert_eq!(
        format!(
            "{:?}",
            "tls://www.baidu.com/path/a?cipher=a&cipher=b&key=/path/to/key".parse::<TransportAcceptorConfig>()
        ),
        "Err(\"transport tls cert not configured\")"
    );
}
