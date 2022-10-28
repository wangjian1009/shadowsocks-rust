use std::io;
use tokio_rustls::rustls::{CipherSuite, SupportedCipherSuite, ALL_CIPHER_SUITES};

pub fn get_cipher_name(cipher: &SupportedCipherSuite) -> &'static str {
    // A list of all the cipher suites supported by rustls.
    // pub static ALL_CIPHERSUITES: [&SupportedCipherSuite; 9] = [
    // TLS1.3 suites
    // &TLS13_CHACHA20_POLY1305_SHA256,
    // &TLS13_AES_256_GCM_SHA384,
    // &TLS13_AES_128_GCM_SHA256,
    //
    // TLS1.2 suites
    // &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    // &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    // &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    // &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    // &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    // &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    // ];
    match cipher.suite() {
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS13_CHACHA20_POLY1305_SHA256",
        CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS13_AES_256_GCM_SHA384",
        CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS13_AES_128_GCM_SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        _ => "???",
    }
}

pub fn get_cipher_suite(cipher: Option<Vec<&str>>) -> io::Result<Vec<SupportedCipherSuite>> {
    if cipher.is_none() {
        return Ok(ALL_CIPHER_SUITES.to_vec());
    }
    let cipher = cipher.unwrap();
    let mut result = Vec::new();

    for name in cipher {
        let mut found = false;
        for i in ALL_CIPHER_SUITES {
            if name == get_cipher_name(i) {
                result.push(i.clone());
                found = true;
                tracing::debug!("cipher: {} applied", name);
                break;
            }
        }
        if !found {
            return Err(io::Error::new(io::ErrorKind::Other, format!("bad cipher: {}", name)));
        }
    }
    Ok(result)
}
