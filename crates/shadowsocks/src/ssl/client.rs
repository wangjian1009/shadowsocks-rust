use rustls_pemfile::Item;
use std::{
    fs::{self, File},
    io,
    sync::Arc,
};

use rustls::{version::TLS13, Certificate, ClientConfig, RootCertStore, SupportedCipherSuite};

pub fn load_certificates(files: &Vec<String>) -> io::Result<RootCertStore> {
    let mut certs = RootCertStore::empty();

    for file in files {
        let mut file = io::BufReader::new(File::open(file)?);

        while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
            if let Item::X509Certificate(cert) = item {
                certs
                    .add(&Certificate(cert))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("load_certifications: {e}")))?;
            }
        }
    }

    if certs.is_empty() {
        for file in files {
            certs
                .add(&Certificate(fs::read(file)?))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("load_certifications: {e}")))?;
        }
    }

    for cert in rustls_native_certs::load_native_certs()? {
        certs
            .add(&Certificate(cert.0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("load_certifications: native: {e}")))?;
    }

    Ok(certs)
}

pub fn build_config(
    certs: Option<RootCertStore>,
    cipher_suites: &[SupportedCipherSuite],
    alpn: Option<Vec<Vec<u8>>>,
) -> io::Result<ClientConfig> {
    let crypto = rustls::ClientConfig::builder();

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

            b.with_custom_certificate_verifier(Arc::new(NoVerifier {}) as Arc<dyn rustls::client::ServerCertVerifier>)
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

impl rustls::client::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
