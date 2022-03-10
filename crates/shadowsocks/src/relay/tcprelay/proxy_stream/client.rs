//! TCP stream for communicating with shadowsocks' proxy server

use std::{
    io::{self, ErrorKind},
    pin::Pin,
    task::{self, Poll},
};

use bytes::{BufMut, BytesMut};
use futures::ready;
use log::trace;
use once_cell::sync::Lazy;
use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time,
};

use crate::{
    config::{ServerConfig, ShadowsocksConfig},
    context::SharedContext,
    net::{ConnectOpts, Destination},
    relay::{socks5::Address, tcprelay::crypto_io::CryptoStream},
    transport::{Connection, Connector, StreamConnection},
};

enum ProxyClientStreamWriteState {
    Connect(Address),
    Connecting(BytesMut),
    Connected,
}

/// A stream for sending / receiving data stream from remote server via shadowsocks' proxy server
#[pin_project]
pub struct ProxyClientStream<S> {
    #[pin]
    stream: CryptoStream<S>,
    state: ProxyClientStreamWriteState,
    context: SharedContext,
}

static DEFAULT_CONNECT_OPTS: Lazy<ConnectOpts> = Lazy::new(Default::default);

impl<S: StreamConnection> StreamConnection for ProxyClientStream<S> {
    fn local_addr(&self) -> io::Result<Destination> {
        self.stream.get_ref().local_addr()
    }

    fn check_connected(&self) -> bool {
        self.stream.get_ref().check_connected()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, limiter: Option<std::sync::Arc<crate::transport::RateLimiter>>) {
        self.stream.get_mut().set_rate_limit(limiter);
    }
}

impl<S: StreamConnection> ProxyClientStream<S> {
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect<C>(
        context: SharedContext,
        connector: &C,
        svr_cfg: &ServerConfig,
        svr_ss_cfg: &ShadowsocksConfig,
        addr: Address,
    ) -> io::Result<ProxyClientStream<S>>
    where
        C: Connector + Connector<TS = S>,
    {
        ProxyClientStream::connect_with_opts(context, connector, svr_cfg, svr_ss_cfg, addr, &DEFAULT_CONNECT_OPTS).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_with_opts<C>(
        context: SharedContext,
        connector: &C,
        svr_cfg: &ServerConfig,
        svr_ss_cfg: &ShadowsocksConfig,
        addr: Address,
        opts: &ConnectOpts,
    ) -> io::Result<ProxyClientStream<S>>
    where
        C: Connector + Connector<TS = S>,
    {
        ProxyClientStream::connect_with_opts_map(context, connector, svr_cfg, svr_ss_cfg, addr, opts, |s| s).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`, maps `TcpStream` to customized stream with `map_fn`
    pub async fn connect_map<C, F>(
        context: SharedContext,
        connector: &C,
        svr_cfg: &ServerConfig,
        svr_ss_cfg: &ShadowsocksConfig,
        addr: Address,
        map_fn: F,
    ) -> io::Result<ProxyClientStream<S>>
    where
        C: Connector + Connector<TS = S>,
        F: FnOnce(C::TS) -> S,
    {
        ProxyClientStream::connect_with_opts_map(
            context,
            connector,
            svr_cfg,
            svr_ss_cfg,
            addr,
            &DEFAULT_CONNECT_OPTS,
            map_fn,
        )
        .await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`, maps `TcpStream` to customized stream with `map_fn`
    pub async fn connect_with_opts_map<C, F>(
        context: SharedContext,
        connector: &C,
        svr_cfg: &ServerConfig,
        svr_ss_cfg: &ShadowsocksConfig,
        addr: Address,
        opts: &ConnectOpts,
        map_fn: F,
    ) -> io::Result<ProxyClientStream<S>>
    where
        C: Connector,
        F: FnOnce(C::TS) -> S,
    {
        let destination = Destination::Tcp(svr_cfg.external_addr().clone());

        let stream = match svr_cfg.timeout() {
            Some(d) => match time::timeout(d, connector.connect(&destination, opts)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(e),
                Err(..) => {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        format!("connect {} timeout", svr_cfg.addr()),
                    ))
                }
            },
            None => connector.connect(&destination, opts).await?,
        };

        trace!(
            "connected tcp remote {} (outbound: {}) with {:?}",
            svr_cfg.addr(),
            svr_cfg.external_addr(),
            opts
        );

        match stream {
            Connection::Stream(stream) => Ok(ProxyClientStream::from_stream(
                context,
                map_fn(stream),
                svr_ss_cfg,
                addr,
            )),
            Connection::Packet { .. } => panic!(),
        }
    }

    /// Create a `ProxyClientStream` with a connected `stream` to a shadowsocks' server
    ///
    /// NOTE: `stream` must be connected to the server with the same configuration as `svr_cfg`, otherwise strange errors would occurs
    pub fn from_stream(
        context: SharedContext,
        stream: S,
        svr_ss_cfg: &ShadowsocksConfig,
        addr: Address,
    ) -> ProxyClientStream<S> {
        let stream = CryptoStream::from_stream(&context, stream, svr_ss_cfg.method(), svr_ss_cfg.key());

        ProxyClientStream {
            stream,
            state: ProxyClientStreamWriteState::Connect(addr),
            context,
        }
    }

    /// Get reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Get mutable reference to the underlying stream
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Consumes the `ProxyClientStream` and return the underlying stream
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }
}

impl<S> AsyncRead for ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        this.stream.poll_read_decrypted(cx, this.context, buf)
    }
}

impl<S> AsyncWrite for ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let mut this = self.project();

        loop {
            match this.state {
                ProxyClientStreamWriteState::Connect(ref addr) => {
                    // Target Address should be sent with the first packet together,
                    // which would prevent from being detected by connection features.

                    let addr_length = addr.serialized_len();

                    let mut buffer = BytesMut::with_capacity(addr_length + buf.len());
                    addr.write_to_buf(&mut buffer);
                    buffer.put_slice(buf);

                    // Save the concatenated buffer before it is written successfully.
                    // APIs require buffer to be kept alive before Poll::Ready
                    //
                    // Proactor APIs like IOCP on Windows, pointers of buffers have to be kept alive
                    // before IO completion.
                    *(this.state) = ProxyClientStreamWriteState::Connecting(buffer);
                }
                ProxyClientStreamWriteState::Connecting(ref buffer) => {
                    let n = ready!(this.stream.poll_write_encrypted(cx, buffer))?;

                    // In general, poll_write_encrypted should perform like write_all.
                    debug_assert!(n == buffer.len());

                    *(this.state) = ProxyClientStreamWriteState::Connected;

                    // NOTE:
                    // poll_write will return Ok(0) if buf.len() == 0
                    // But for the first call, this function will eventually send the handshake packet (IV/Salt + ADDR) to the remote address.
                    //
                    // https://github.com/shadowsocks/shadowsocks-rust/issues/232
                    //
                    // For protocols that requires *Server Hello* message, like FTP, clients won't send anything to the server until server sends handshake messages.
                    // This could be achieved by calling poll_write with an empty input buffer.
                    return Ok(buf.len()).into();
                }
                ProxyClientStreamWriteState::Connected => {
                    return this.stream.poll_write_encrypted(cx, buf);
                }
            }
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }
}
