use async_trait::async_trait;
use std::{io, sync::Arc};
use tokio_rustls::{
    client::TlsStream,
    rustls::{pki_types::ServerName, ClientConfig},
};

use crate::{net::ConnectOpts, rustls_util, ServerAddr};

use super::super::{AsyncPing, Connector, DeviceOrGuard, StreamConnection};

#[derive(Clone, Debug, PartialEq)]
pub struct TlsConnectorConfig {
    pub sni: Option<String>,
    pub cert: Option<String>,
}

pub struct TlsConnector<C: Connector> {
    sni: Option<String>,
    client_config: Arc<ClientConfig>,
    inner: C,
}

impl<S: StreamConnection> StreamConnection for TlsStream<S> {
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

impl<S: StreamConnection> AsyncPing for TlsStream<S> {}

impl<C: Connector> TlsConnector<C> {
    pub fn new(config: &TlsConnectorConfig, inner: C) -> io::Result<Self> {
        let client_config = rustls_util::create_client_config(false, &[], config.sni.is_some())?;

        Ok(Self {
            sni: config.sni.clone(),
            client_config: Arc::new(client_config),
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
    type TS = TlsStream<S>;

    async fn connect(&self, destination: &ServerAddr, connect_opts: &ConnectOpts) -> io::Result<Self::TS> {
        let stream = self.inner.connect(destination, connect_opts).await?;

        let server_name = if let Some(sni) = self.sni.as_ref() {
            ServerName::try_from(sni.as_str()).map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?
        } else {
            match destination {
                ServerAddr::SocketAddr(sa) => ServerName::IpAddress(sa.ip().into()),
                ServerAddr::DomainName(ref dname, _) => ServerName::try_from(dname.as_str())
                    .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?,
            }
        };

        let tls_connector: tokio_rustls::TlsConnector = self.client_config.clone().into();

        let tls_stream = tls_connector
            .connect_with(server_name.to_owned(), stream, |client_conn| {
                client_conn.set_buffer_limit(Some(32768));
            })
            .await?;

        Ok(tls_stream)
    }
}
