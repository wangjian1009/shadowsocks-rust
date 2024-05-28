use super::super::Acceptor;
use crate::{
    canceler::Canceler, context::Context, net::{AcceptOpts, TcpListener}, ServerAddr
};
use std::{io, net::SocketAddr};

use async_trait::async_trait;
use once_cell::sync::Lazy;

pub struct TcpAcceptor {
    inner: TcpListener,
}

#[cfg(feature = "rate-limit")]
use super::super::RateLimitedStream;

#[async_trait]
impl Acceptor for TcpAcceptor {
    #[cfg(feature = "rate-limit")]
    type TS = RateLimitedStream<tokio::net::TcpStream>;
    #[cfg(not(feature = "rate-limit"))]
    type TS = tokio::net::TcpStream;

    async fn accept(&mut self) -> io::Result<(Self::TS, Option<SocketAddr>)> {
        let (stream, addr) = self.inner.accept().await?;

        #[cfg(feature = "rate-limit")]
        let stream = RateLimitedStream::from_stream(stream, None);

        Ok((stream, Some(addr)))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

static DEFAULT_ACCEPT_OPTS: Lazy<AcceptOpts> = Lazy::new(Default::default);

impl TcpAcceptor {
    /// Creates a new TcpAcceptor, which will be bound to the specified address.
    pub async fn bind(addr: &SocketAddr) -> io::Result<TcpAcceptor> {
        Self::bind_with_opts(addr, DEFAULT_ACCEPT_OPTS.clone()).await
    }

    /// Creates a new TcpAcceptor, which will be bound to the specified address.
    pub async fn bind_with_opts(addr: &SocketAddr, accept_opts: AcceptOpts) -> io::Result<TcpAcceptor> {
        let inner = TcpListener::bind_with_opts(addr, accept_opts).await?;
        Ok(TcpAcceptor { inner })
    }

    pub async fn bind_server(context: &Context, addr: &ServerAddr, canceler: &Canceler) -> io::Result<TcpAcceptor> {
        Self::bind_server_with_opts(context, addr, DEFAULT_ACCEPT_OPTS.clone(), canceler).await
    }

    pub async fn bind_server_with_opts(
        context: &Context,
        addr: &ServerAddr,
        accept_opts: AcceptOpts,
        canceler: &Canceler,
    ) -> io::Result<TcpAcceptor> {
        match addr {
            ServerAddr::SocketAddr(addr) => Self::bind_with_opts(addr, accept_opts).await,
            ServerAddr::DomainName(domain, port) => Ok(lookup_then!(context, domain, *port, canceler, |addr| {
                Self::bind_with_opts(&addr, accept_opts.clone()).await
            })?
            .1),
        }
    }
}
