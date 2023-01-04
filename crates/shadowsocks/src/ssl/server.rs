use rustls_pemfile::Item;
use std::io;
use std::{
    fs::{self, File},
    io::{BufReader, Error as IoError},
};
use tokio_rustls::rustls::{version::TLS13, Certificate, PrivateKey, ServerConfig, SupportedCipherSuite};

pub fn load_certificates(path: &str) -> Result<Vec<Certificate>, IoError> {
    let mut file = BufReader::new(File::open(path)?);
    let mut certs = Vec::new();

    while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
        if let Item::X509Certificate(cert) = item {
            certs.push(Certificate(cert));
        }
    }

    if certs.is_empty() {
        certs = vec![Certificate(fs::read(path)?)];
    }

    Ok(certs)
}

pub fn load_private_key(path: &str) -> Result<PrivateKey, IoError> {
    let mut file = BufReader::new(File::open(path)?);
    let mut priv_key = None;

    while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
        if let Item::RSAKey(key) | Item::PKCS8Key(key) | Item::ECKey(key) = item {
            priv_key = Some(key);
        }
    }

    priv_key.map(Ok).unwrap_or_else(|| fs::read(path)).map(PrivateKey)
}

pub fn build_config(
    certs: Vec<Certificate>,
    priv_key: PrivateKey,
    cipher_suites: &[SupportedCipherSuite],
    alpn: Option<Vec<Vec<u8>>>,
) -> io::Result<ServerConfig> {
    let crypto = ServerConfig::builder();

    let crypto = crypto.with_cipher_suites(cipher_suites);

    let mut crypto = crypto
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, priv_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    crypto.max_early_data_size = u32::MAX;

    if let Some(alpn) = alpn {
        crypto.alpn_protocols = alpn;
    }

    Ok(crypto)
}
