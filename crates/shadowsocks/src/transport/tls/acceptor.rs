use async_trait::async_trait;
use std::{io, net::SocketAddr, sync::Arc};
use tokio_rustls::{server::TlsStream as TokioTlsStream, TlsAcceptor as TokioTlsAcceptor};

use crate::{ssl, ServerAddr};

use super::super::{Acceptor, Connection, DeviceOrGuard, DummyPacket, StreamConnection};

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
        loop {
            let (stream, addr) = self.inner.accept().await?;
            match stream {
                Connection::Stream(stream) => {
                    let stream = match self.tls_acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(err) => {
                            tracing::debug!(error = ?err, "tls accept connection fail");
                            continue;
                        }
                    };
                    return Ok((Connection::Stream(stream), addr));
                }
                Connection::Packet { .. } => unimplemented!(),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl<T: Acceptor> TlsAcceptor<T> {
    pub async fn new(config: &TlsAcceptorConfig, inner: T) -> io::Result<Self> {
        let certs = ssl::server::load_certificates(&config.cert)?;
        let priv_key = ssl::server::load_private_key(&config.key)?;

        let cipher_suites =
            ssl::get_cipher_suite(config.cipher.as_ref().map(|vs| vs.iter().map(|f| f.as_str()).collect()))?;

        let tls_config = ssl::server::build_config(certs, priv_key, Some(cipher_suites.as_slice()), None)?;

        let tls_acceptor = TokioTlsAcceptor::from(Arc::new(tls_config));
        Ok(Self { inner, tls_acceptor })
    }
}
