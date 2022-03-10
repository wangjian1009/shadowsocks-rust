use async_trait::async_trait;
use std::{io, net::SocketAddr, path::Path, sync::Arc};
use tokio_rustls::{
    rustls::{NoClientAuth, ServerConfig},
    server::TlsStream as TokioTlsStream,
    TlsAcceptor as TokioTlsAcceptor,
};

use crate::{net::Destination, ServerAddr};

use super::{
    super::{Acceptor, Connection, DummyPacket, StreamConnection},
    get_cipher_suite,
    load_cert,
    load_key,
    new_error,
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

#[async_trait]
impl<T, S> Acceptor for TlsAcceptor<T>
where
    S: StreamConnection + 'static,
    T: Acceptor + Acceptor<TS = S>,
{
    type PR = DummyPacket;
    type PW = DummyPacket;
    type TS = TokioTlsStream<S>;

    async fn accept(&self) -> io::Result<(Connection<Self::TS, Self::PR, Self::PW>, Option<ServerAddr>)> {
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
        let cert_path = Path::new(&config.cert);
        let key_path = Path::new(&config.key);
        let certs = load_cert(&cert_path)?;
        let mut keys = load_key(&key_path)?;

        let mut tls_config = ServerConfig::new(NoClientAuth::new());
        tls_config
            .set_single_cert(certs, keys.remove(0))
            .map_err(|e| new_error(format!("invalid cert {}", e.to_string())))?;

        tls_config.ciphersuites =
            get_cipher_suite(config.cipher.as_ref().map(|vs| vs.iter().map(|f| f.as_str()).collect()))?;

        let tls_acceptor = TokioTlsAcceptor::from(Arc::new(tls_config));
        Ok(Self { inner, tls_acceptor })
    }
}
