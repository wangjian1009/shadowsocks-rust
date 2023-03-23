use rustls_pemfile::Item;
use std::{
    fs::{self, File},
    io,
    sync::Arc,
};

use tokio_rustls::rustls::{version::TLS13, Certificate, ClientConfig, RootCertStore, SupportedCipherSuite};

pub fn load_certificates(files: &Vec<String>) -> io::Result<RootCertStore> {
    let mut certs = RootCertStore::empty();

    for file in files {
        let mut file = io::BufReader::new(File::open(file)?);

        while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
            if let Item::X509Certificate(cert) = item {
                certs
                    .add(&Certificate(cert))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("load_certifications: {}", e)))?;
            }
        }
    }

    if certs.is_empty() {
        for file in files {
            certs
                .add(&Certificate(fs::read(file)?))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("load_certifications: {}", e)))?;
        }
    }

    for cert in rustls_native_certs::load_native_certs()? {
        certs
            .add(&Certificate(cert.0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("load_certifications: native: {}", e)))?;
    }

    Ok(certs)
}

pub fn build_config(
    certs: Option<RootCertStore>,
    cipher_suites: &[SupportedCipherSuite],
    alpn: Option<Vec<Vec<u8>>>,
) -> io::Result<ClientConfig> {
    let crypto = tokio_rustls::rustls::ClientConfig::builder();

    let crypto = crypto.with_cipher_suites(cipher_suites);

    let mut crypto = crypto
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS13])
        .map(|b| {
            if let Some(certs) = certs {
                if !certs.is_empty() {
                    return b.with_root_certificates(certs).with_no_client_auth();
                }
            }

            b.with_custom_certificate_verifier(
                Arc::new(NoVerifier {}) as Arc<dyn tokio_rustls::rustls::client::ServerCertVerifier>
            )
            .with_no_client_auth()
        })
        .unwrap();

    if let Some(alpn) = alpn {
        crypto.alpn_protocols = alpn;
    }

    crypto.enable_early_data = true;
    // crypto.enable_sni = !raw.disable_sni;

    Ok(crypto)
}

pub(crate) struct NoVerifier;

impl tokio_rustls::rustls::client::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::Certificate,
        _intermediates: &[tokio_rustls::rustls::Certificate],
        _server_name: &tokio_rustls::rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<tokio_rustls::rustls::client::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::ServerCertVerified::assertion())
    }
}
