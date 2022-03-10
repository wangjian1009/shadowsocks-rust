use async_trait::async_trait;
use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
    sync::Arc,
};
use tokio_rustls::{
    client::TlsStream as TokioTlsStream,
    rustls::{Certificate, ClientConfig, RootCertStore, ServerCertVerified, ServerCertVerifier, TLSError},
    TlsConnector as TokioTlsConnector,
};
use webpki::DNSNameRef;

use crate::net::{ConnectOpts, Destination};

use super::{
    super::{Connection, Connector, DummyPacket, StreamConnection},
    get_cipher_suite,
    new_error,
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
    fn local_addr(&self) -> io::Result<Destination> {
        self.get_ref().0.local_addr()
    }

    fn check_connected(&self) -> bool {
        self.get_ref().0.check_connected()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<std::sync::Arc<crate::transport::RateLimiter>>) {
        self.get_mut().0.set_rate_limit(rate_limit);
    }
}

struct NoServerVerifier {}

impl ServerCertVerifier for NoServerVerifier {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        _presented_certs: &[Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

impl<C: Connector> TlsConnector<C> {
    pub fn new(config: &TlsConnectorConfig, inner: C) -> io::Result<Self> {
        let mut tls_config = ClientConfig::new();

        tls_config.ciphersuites =
            get_cipher_suite(config.cipher.as_ref().map(|vs| vs.iter().map(|f| f.as_str()).collect()))?;

        if let Some(ref cert_path) = config.cert {
            let cert_path = Path::new(cert_path);
            tls_config
                .root_store
                .add_pem_file(&mut BufReader::new(
                    File::open(cert_path)
                        .map_err(|e| new_error(format!("open tls cert {:?} fail, {}", cert_path, e)))?,
                ))
                .unwrap();
        } else {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoServerVerifier {}));
        }

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
                let dns_name = DNSNameRef::try_from_ascii_str(&self.sni)
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
