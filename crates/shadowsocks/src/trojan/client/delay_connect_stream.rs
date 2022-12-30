use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};

use bytes::{BufMut, BytesMut};
use futures::ready;
use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time,
};
use tracing::error;

use crate::{
    config::ServerConfig,
    net::ConnectOpts,
    transport::{Connector, DeviceOrGuard, StreamConnection},
    ServerAddr,
};

use super::super::{
    protocol::{Address, RequestHeader},
    Config,
};

enum ClientStreamWriteState {
    Connect(RequestHeader),
    Connecting(BytesMut),
    Connected,
}

/// A stream for sending / receiving data stream from remote server via trojan' proxy server
#[pin_project]
pub struct DelayConnectStream<S> {
    #[pin]
    stream: S,
    state: ClientStreamWriteState,
}

impl<S: StreamConnection> StreamConnection for DelayConnectStream<S> {
    fn check_connected(&self) -> bool {
        self.stream.check_connected()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, limiter: Option<std::sync::Arc<crate::transport::RateLimiter>>) {
        self.stream.set_rate_limit(limiter);
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        self.stream.physical_device()
    }
}

impl<S: StreamConnection> DelayConnectStream<S> {
    /// Connect to target `addr` via trojan' server configured by `svr_cfg`, maps `TcpStream` to customized stream with `map_fn`
    pub async fn connect_stream<C, F>(
        connector: &C,
        svr_cfg: &ServerConfig,
        svr_trojan_cfg: &Config,
        addr: ServerAddr,
        opts: &ConnectOpts,
        map_fn: F,
    ) -> io::Result<DelayConnectStream<S>>
    where
        C: Connector,
        F: FnOnce(C::TS) -> S,
    {
        let stream = match time::timeout(svr_cfg.timeout(), connector.connect(svr_cfg.external_addr(), opts)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                error!(error = ?e, "connect error");
                return Err(e);
            }
            Err(e) => {
                error!(error = ?e, "connect timeout");
                return Err(io::ErrorKind::TimedOut.into());
            }
        };

        Ok(DelayConnectStream::new_stream(map_fn(stream), svr_trojan_cfg, addr))
    }

    fn new_stream(stream: S, svr_trojan_cfg: &Config, addr: ServerAddr) -> DelayConnectStream<S> {
        DelayConnectStream {
            stream,
            state: ClientStreamWriteState::Connect(RequestHeader::TcpConnect(
                svr_trojan_cfg.hash(),
                Address::from(addr),
            )),
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }
}

impl<S> AsyncRead for DelayConnectStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        this.stream.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for DelayConnectStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let this = self.project();

        loop {
            match this.state {
                ClientStreamWriteState::Connect(ref request) => {
                    let request_length = request.serialized_len();

                    let mut buffer = BytesMut::with_capacity(request_length + buf.len());
                    request.write_to_buf(&mut buffer);
                    buffer.put_slice(buf);

                    *(this.state) = ClientStreamWriteState::Connecting(buffer);
                }
                ClientStreamWriteState::Connecting(ref buffer) => {
                    let n = ready!(this.stream.poll_write(cx, buffer))?;

                    // In general, poll_write_encrypted should perform like write_all.
                    debug_assert!(n == buffer.len());

                    *(this.state) = ClientStreamWriteState::Connected;

                    return Ok(buf.len()).into();
                }
                ClientStreamWriteState::Connected => {
                    return this.stream.poll_write(cx, buf);
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
