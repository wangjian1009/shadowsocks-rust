use async_trait::async_trait;
use std::{io, sync::Arc};
use tokio_rustls::{
    client::TlsStream as TokioTlsStream,
    rustls::{ClientConfig, ServerName},
    TlsConnector as TokioTlsConnector,
};

use crate::{
    net::{ConnectOpts, Destination},
    ssl,
};

use super::super::{Connection, Connector, DeviceOrGuard, DummyPacket, StreamConnection};

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

impl<C: Connector> TlsConnector<C> {
    pub fn new(config: &TlsConnectorConfig, inner: C) -> io::Result<Self> {
        let cipher_suites =
            ssl::get_cipher_suite(config.cipher.as_ref().map(|vs| vs.iter().map(|f| f.as_str()).collect()))?;

        let mut certs = None;
        if let Some(cert_file) = config.cert.as_ref() {
            certs = Some(ssl::client::load_certificates(&vec![cert_file.clone()])?);
        };

        let tls_config = ssl::client::build_config(certs, Some(cipher_suites.as_slice()), None)?;

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
