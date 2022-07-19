use async_trait::async_trait;
use rustls_pemfile::Item;
use std::{
    fs::{self, File},
    io::{self, BufReader},
    net::SocketAddr,
    sync::Arc,
};
use tokio_rustls::{
    rustls::{Certificate, PrivateKey, ServerConfig},
    server::TlsStream as TokioTlsStream,
    TlsAcceptor as TokioTlsAcceptor,
};

use crate::ServerAddr;

use super::{
    super::{Acceptor, Connection, DeviceOrGuard, DummyPacket, StreamConnection},
    get_cipher_suite, new_error,
};

#[derive(Clone, Debug, PartialEq)]
pub struct TlsAcceptorConfig {
    pub cert: String,
    pub key: String,
    pub cipher: Option<Vec<String>>,
}

pub struct TlsAcceptor<T: Acceptor> {
    tls_acceptor: TokioTlsAcceptor,
    inner: T,
}

impl<S: StreamConnection> StreamConnection for TokioTlsStream<S> {
    fn check_connected(&self) -> bool {
        self.get_ref().0.check_connected()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<std::sync::Arc<crate::transport::RateLimiter>>) {
        self.get_mut().0.set_rate_limit(rate_limit);
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        self.get_ref().0.physical_device()
    }
}

#[async_trait]
impl<T, S> Acceptor for TlsAcceptor<T>
where
    S: StreamConnection + 'static,
    T: Acceptor + Acceptor<TS = S>,
{
    type PR = DummyPacket;
    type PW = DummyPacket;
    type TS = TokioTlsStream<S>;

    async fn accept(&mut self) -> io::Result<(Connection<Self::TS, Self::PR, Self::PW>, Option<ServerAddr>)> {
        let (stream, addr) = self.inner.accept().await?;
        match stream {
            Connection::Stream(stream) => {
                let stream = self.tls_acceptor.accept(stream).await?;
                Ok((Connection::Stream(stream), addr))
            }
            Connection::Packet { .. } => unimplemented!(),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl<T: Acceptor> TlsAcceptor<T> {
    pub async fn new(config: &TlsAcceptorConfig, inner: T) -> io::Result<Self> {
        let certs = load_certificates(&config.cert)?;
        let priv_key = load_private_key(&config.key)?;

        let cipher_suites = get_cipher_suite(config.cipher.as_ref().map(|vs| vs.iter().map(|f| f.as_str()).collect()))?;

        let tls_config = ServerConfig::builder()
            .with_cipher_suites(&cipher_suites)
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)
            .map_err(|e| new_error(format!("build tls server config fail: {}", e)))?;

        let tls_acceptor = TokioTlsAcceptor::from(Arc::new(tls_config));
        Ok(Self { inner, tls_acceptor })
    }
}

fn load_certificates(path: &str) -> io::Result<Vec<Certificate>> {
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

fn load_private_key(path: &str) -> io::Result<PrivateKey> {
    let mut file = BufReader::new(File::open(path)?);
    let mut priv_key = None;

    while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
        if let Item::RSAKey(key) | Item::PKCS8Key(key) | Item::ECKey(key) = item {
            priv_key = Some(key);
        }
    }

    priv_key.map(Ok).unwrap_or_else(|| fs::read(path)).map(PrivateKey)
}
