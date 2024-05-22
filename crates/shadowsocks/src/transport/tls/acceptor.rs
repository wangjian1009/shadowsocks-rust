use async_trait::async_trait;
use std::{io, net::SocketAddr, sync::Arc};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_rustls::{server::TlsStream as TokioTlsStream, TlsAcceptor as TokioTlsAcceptor};
use tracing::Instrument;

use crate::{
    canceler::{CancelWaiter, Canceler},
    rustls_util,
};

use super::super::{Acceptor, AsyncPing, DeviceOrGuard, StreamConnection};

#[derive(Clone, Debug, PartialEq)]
pub struct TlsAcceptorConfig {
    pub cert: String,
    pub key: String,
}

pub struct TlsAcceptor<T: Acceptor> {
    tls_acceptor: Arc<TokioTlsAcceptor>,
    inner: T,
    tls_stream_rx: Receiver<(TokioTlsStream<T::TS>, Option<SocketAddr>)>,
    tls_stream_tx: Sender<(TokioTlsStream<T::TS>, Option<SocketAddr>)>,
    canceler: Canceler,
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

impl<S: StreamConnection> AsyncPing for TokioTlsStream<S> {}

#[async_trait]
impl<T, S> Acceptor for TlsAcceptor<T>
where
    S: StreamConnection + 'static,
    T: Acceptor + Acceptor<TS = S>,
{
    type TS = TokioTlsStream<S>;

    async fn accept(&mut self) -> io::Result<(Self::TS, Option<SocketAddr>)> {
        loop {
            tokio::select! {
                r = self.inner.accept() => {
                    let (stream, addr) = r?;

                    let tls_acceptor = self.tls_acceptor.clone();
                    let tls_stream_tx = self.tls_stream_tx.clone();
                    let cancel_waiter = self.canceler.waiter();

                    tokio::spawn(async move {
                        Self::accept_tls_stream(tls_acceptor, tls_stream_tx, stream, addr, cancel_waiter).await;
                    }.in_current_span());
                }
                r = self.tls_stream_rx.recv() => {
                    if let Some((stream, addr)) = r {
                        return Ok((stream, addr));
                    }
                    else {
                        tracing::error!("tls receive new connection return non");
                        return Err(io::Error::new(io::ErrorKind::Other, "tls receive new connection error"));
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl<T: Acceptor> TlsAcceptor<T> {
    pub async fn new(config: &TlsAcceptorConfig, inner: T) -> io::Result<Self> {
        let cert = match tokio::fs::read(config.cert.as_str()).await {
            Ok(cert) => cert,
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("failed to read cert file: {}, path={}", err, config.cert),
                ));
            }
        };

        let key = match tokio::fs::read(config.key.as_str()).await {
            Ok(key) => key,
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("failed to read key file: {}, path={}", err, config.key),
                ));
            }
        };
        
        let tls_config = rustls_util::create_server_config(cert.as_slice(), key.as_slice(), &[])?;

        let (tls_stream_tx, tls_stream_rx) = mpsc::channel(1);

        let tls_acceptor = Arc::new(TokioTlsAcceptor::from(Arc::new(tls_config)));
        Ok(Self {
            inner,
            tls_acceptor,
            tls_stream_rx,
            tls_stream_tx,
            canceler: Canceler::new(),
        })
    }

    async fn accept_tls_stream(
        tls_acceptor: Arc<TokioTlsAcceptor>,
        tls_stream_tx: Sender<(TokioTlsStream<T::TS>, Option<SocketAddr>)>,
        base_stream: T::TS,
        source_addr: Option<SocketAddr>,
        mut cancel_waiter: CancelWaiter,
    ) {
        tokio::select! {
            _ = cancel_waiter.wait() => {
            },
            r = tls_acceptor.accept(base_stream) => {
                match r {
                    Ok(stream) => {
                        if let Err(_err) = tls_stream_tx.send((stream, source_addr)).await {
                            tracing::error!("tls send accepted stream fail");
                        }
                    }
                    Err(err) => {
                        tracing::error!(error = ?err, "tls accept connection fail");
                    }
                }
            }
        }
    }
}

impl<T: Acceptor> Drop for TlsAcceptor<T> {
    fn drop(&mut self) {
        self.canceler.cancel();
    }
}
