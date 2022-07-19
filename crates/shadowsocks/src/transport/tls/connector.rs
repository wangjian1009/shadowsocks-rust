use async_trait::async_trait;
use rustls_pemfile::Item;
use std::{
    fs::{self, File},
    io::{self, BufReader},
    sync::Arc,
};
use tokio_rustls::{
    client::TlsStream as TokioTlsStream,
    rustls::{Certificate, ClientConfig, RootCertStore, ServerName},
    TlsConnector as TokioTlsConnector,
};

use crate::net::{ConnectOpts, Destination};

use super::{
    super::{Connection, Connector, DeviceOrGuard, DummyPacket, StreamConnection},
    get_cipher_suite,
};

#[derive(Clone, Debug, PartialEq)]
pub struct TlsConnectorConfig {
    pub sni: String,
    pub cipher: Option<Vec<String>>,
    pub cert: Option<String>,
}

pub struct TlsConnector<C: Connector> {
    sni: String,
    tls_config: Arc<ClientConfig>,
    inner: C,
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

fn load_certificates(files: Vec<String>) -> io::Result<RootCertStore> {
    let mut certs = RootCertStore::empty();

    for file in &files {
        let mut file = BufReader::new(File::open(file)?);

        while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
            if let Item::X509Certificate(cert) = item {
                certs
                    .add(&Certificate(cert))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }
        }
    }

    if certs.is_empty() {
        for file in &files {
            certs
                .add(&Certificate(fs::read(file)?))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
    }

    for cert in rustls_native_certs::load_native_certs().map_err(|e| io::Error::new(io::ErrorKind::Other, e))? {
        certs
            .add(&Certificate(cert.0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }

    Ok(certs)
}

impl<C: Connector> TlsConnector<C> {
    pub fn new(config: &TlsConnectorConfig, inner: C) -> io::Result<Self> {
        let cipher_suites = get_cipher_suite(config.cipher.as_ref().map(|vs| vs.iter().map(|f| f.as_str()).collect()))?;

        let mut cert_files = Vec::new();
        if let Some(cert_file) = config.cert.as_ref() {
            cert_files.push(cert_file.clone());
        }
        let certs = load_certificates(cert_files)?;

        let tls_config = ClientConfig::builder()
            .with_cipher_suites(&cipher_suites)
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(certs)
            .with_no_client_auth();

        Ok(Self {
            sni: config.sni.clone(),
            tls_config: Arc::new(tls_config),
            inner,
        })
    }
}

#[async_trait]
impl<C, S> Connector for TlsConnector<C>
where
    S: StreamConnection + 'static,
    C: Connector + Connector<TS = S>,
{
    type PR = DummyPacket;
    type PW = DummyPacket;
    type TS = TokioTlsStream<S>;

    async fn connect(
        &self,
        destination: &Destination,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Connection<Self::TS, Self::PR, Self::PW>> {
        match self.inner.connect(destination, connect_opts).await? {
            Connection::Stream(stream) => {
                let dns_name = ServerName::try_from(self.sni.as_str())
                    .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
                let stream = TokioTlsConnector::from(self.tls_config.clone())
                    .connect(dns_name, stream)
                    .await?;

                Ok(Connection::Stream(stream))
            }
            Connection::Packet { .. } => unimplemented!(),
        }
    }
}
