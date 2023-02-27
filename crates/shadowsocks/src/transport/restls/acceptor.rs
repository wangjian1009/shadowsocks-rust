use async_trait::async_trait;
use std::{io, net::SocketAddr, sync::Arc};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::codec::Decoder;
use tracing::Instrument;

use crate::{
    context::Context,
    net::{ConnectOpts, TcpStream},
};

use super::{
    super::Acceptor,
    config::RestlsConfig,
    restls::TryHandshake,
    stream::RestlsStream,
    utils::{copy_bidirectional_fallback, TLSCodec},
};

pub struct RestlsAcceptor<T: Acceptor> {
    context: Arc<Context>,
    config: Arc<RestlsConfig>,
    inner: T,
    tls_stream_rx: Receiver<(RestlsStream<T::TS>, Option<SocketAddr>)>,
    tls_stream_tx: Sender<(RestlsStream<T::TS>, Option<SocketAddr>)>,
}

#[async_trait]
impl<T: Acceptor> Acceptor for RestlsAcceptor<T> {
    type TS = RestlsStream<T::TS>;

    async fn accept(&mut self) -> io::Result<(Self::TS, Option<SocketAddr>)> {
        loop {
            tokio::select! {
                r = self.inner.accept() => {
                    let (stream, addr) = r?;

                    let config = self.config.clone();
                    let tls_stream_tx = self.tls_stream_tx.clone();
                    let context = self.context.clone();

                    tokio::spawn(async move {
                        let _ = Self::accept_tls_stream(context, config, tls_stream_tx, stream, addr).await;
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

impl<T: Acceptor> RestlsAcceptor<T> {
    pub async fn new(context: Arc<Context>, config: &RestlsConfig, inner: T) -> io::Result<Self> {
        let (tls_stream_tx, tls_stream_rx) = mpsc::channel(1);

        Ok(Self {
            context,
            config: Arc::new(config.clone()),
            inner,
            tls_stream_tx,
            tls_stream_rx,
        })
    }

    async fn accept_tls_stream(
        context: Arc<Context>,
        options: Arc<RestlsConfig>,
        tls_stream_tx: Sender<(RestlsStream<T::TS>, Option<SocketAddr>)>,
        base_stream: T::TS,
        source_addr: Option<SocketAddr>,
    ) -> io::Result<()> {
        let mut outbound = TLSCodec::new_inbound().framed(
            match TcpStream::connect_server_with_opts(
                context.as_ref(),
                &options.server_hostname,
                &ConnectOpts::default(),
            )
            .await
            {
                Ok(s) => s,
                Err(err) => {
                    tracing::error!(err = ?err, "connect {} failed", options.server_hostname);
                    return Err(err);
                }
            },
        );

        let mut inbound = TLSCodec::new_outbound().framed(base_stream);
        let mut try_handshake = TryHandshake {};
        match try_handshake
            .try_handshake(options.as_ref(), &mut outbound, &mut inbound)
            .await
        {
            Ok(discard) => {
                match tls_stream_tx
                    .send((RestlsStream::new(inbound, discard), source_addr))
                    .await
                {
                    Ok(()) => {}
                    Err(_e) => {
                        tracing::error!("send stream fail");
                    }
                }
            }
            Err(e) => {
                tracing::error!("handshake failed: {}", e);
                let _ = copy_bidirectional_fallback(inbound, outbound).await;
            }
        };

        Ok(())
    }
}
