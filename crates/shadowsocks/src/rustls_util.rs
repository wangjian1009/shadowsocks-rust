use once_cell::sync::OnceCell;
use std::io;
use std::sync::Arc;
use tokio_rustls::rustls::{
    self,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};

pub fn create_client_config(
    verify: bool,
    alpn_protocols: &[String],
    enable_sni: bool,
) -> io::Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder();

    let mut config = if !verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(get_disabled_verifier())
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| ta.to_owned()));
        builder.with_root_certificates(root_store).with_no_client_auth()
    };

    config.alpn_protocols = alpn_protocols.iter().map(|s| s.as_bytes().to_vec()).collect();

    config.enable_early_data = true;

    config.enable_sni = enable_sni;

    Ok(config)
}

#[derive(Debug)]
pub struct DisabledVerifier;

impl ServerCertVerifier for DisabledVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

fn get_disabled_verifier() -> Arc<DisabledVerifier> {
    static INSTANCE: OnceCell<Arc<DisabledVerifier>> = OnceCell::new();
    INSTANCE.get_or_init(|| Arc::new(DisabledVerifier {})).clone()
}

fn load_certs(cert_bytes: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::Cursor::new(cert_bytes);
    let mut certs = vec![];
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
        match item {
            Ok(item) => match item {
                rustls_pemfile::Item::X509Certificate(cert) => {
                    certs.push(cert.to_owned());
                }
                _ => {}
            },
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Error loading certificate: {:?}", e),
                ));
            }
        }
    }

    if cert_bytes.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "No certificates found"));
    } else {
        Ok(certs)
    }
}

fn load_private_key(key_bytes: &[u8]) -> io::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::Cursor::new(key_bytes);
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
        let item = item.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        match item {
            rustls_pemfile::Item::Pkcs8Key(key) => {
                return Ok(PrivateKeyDer::Pkcs8(key.clone_key()));
            }
            rustls_pemfile::Item::Pkcs1Key(key) => {
                return Ok(PrivateKeyDer::Pkcs1(key.clone_key()));
            }
            rustls_pemfile::Item::Sec1Key(key) => {
                return Ok(PrivateKeyDer::Sec1(key.clone_key()));
            }
            _ => {}
        }
    }

    Err(io::Error::new(io::ErrorKind::Other, "No private key found"))
}

pub fn create_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    alpn_protocols: &[String],
) -> io::Result<rustls::ServerConfig> {
    let certs = load_certs(cert_bytes)?;
    let privkey = load_private_key(key_bytes)?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, privkey)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("bad certificate/key: {:?}", e)))?;

    config.alpn_protocols = alpn_protocols.iter().map(|s| s.as_bytes().to_vec()).collect();

    config.max_early_data_size = u32::MAX;

    Ok(config)
}
