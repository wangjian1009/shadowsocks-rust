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

use crate::{
    config::{ServerConfig, TrojanConfig},
    net::{ConnectOpts, Destination},
    relay::Address,
    transport::{Connection, Connector, DeviceOrGuard, StreamConnection},
};

use super::protocol::RequestHeader;

enum ClientStreamWriteState {
    Connect(RequestHeader),
    Connecting(BytesMut),
    Connected,
}

/// A stream for sending / receiving data stream from remote server via trojan' proxy server
#[pin_project]
pub struct ClientStream<S> {
    #[pin]
    stream: S,
    state: ClientStreamWriteState,
}

impl<S: StreamConnection> StreamConnection for ClientStream<S> {
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

impl<S: StreamConnection> ClientStream<S> {
    /// Connect to target `addr` via trojan' server configured by `svr_cfg`, maps `TcpStream` to customized stream with `map_fn`
    pub async fn connect_stream<C, F>(
        connector: &C,
        svr_cfg: &ServerConfig,
        svr_trojan_cfg: &TrojanConfig,
        addr: Address,
        opts: &ConnectOpts,
        map_fn: F,
    ) -> io::Result<ClientStream<S>>
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
                        io::ErrorKind::TimedOut,
                        format!("connect {} timeout", svr_cfg.addr()),
                    ))
                }
            },
            None => connector.connect(&destination, opts).await?,
        };

        tracing::trace!(
            "connected trojan tcp remote {}{} (outbound: {}) with {:?}",
            svr_cfg.addr(),
            svr_cfg.external_addr(),
            svr_cfg.acceptor_transport_tag(),
            opts
        );

        match stream {
            Connection::Stream(stream) => Ok(ClientStream::new_stream(map_fn(stream), svr_trojan_cfg, addr)),
            Connection::Packet { .. } => panic!(),
        }
    }

    /// Connect to target `addr` via trojan' server configured by `svr_cfg`, maps `TcpStream` to customized stream with `map_fn`
    pub async fn connect_packet<C, F>(
        connector: &C,
        svr_cfg: &ServerConfig,
        svr_trojan_cfg: &TrojanConfig,
        opts: &ConnectOpts,
        map_fn: F,
    ) -> io::Result<ClientStream<S>>
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
                        io::ErrorKind::TimedOut,
                        format!("connect {} timeout", svr_cfg.addr()),
                    ))
                }
            },
            None => connector.connect(&destination, opts).await?,
        };

        tracing::trace!(
            "connected trojan tcp remote {}{} (outbound: {}) with {:?}",
            svr_cfg.addr(),
            svr_cfg.external_addr(),
            svr_cfg.acceptor_transport_tag(),
            opts
        );

        match stream {
            Connection::Stream(stream) => Ok(ClientStream::new_packet(map_fn(stream), svr_trojan_cfg)),
            Connection::Packet { .. } => panic!(),
        }
    }

    pub fn new_stream(stream: S, svr_trojan_cfg: &TrojanConfig, addr: Address) -> ClientStream<S> {
        ClientStream {
            stream,
            state: ClientStreamWriteState::Connect(RequestHeader::TcpConnect(svr_trojan_cfg.hash().clone(), addr)),
        }
    }

    pub fn new_packet(stream: S, svr_trojan_cfg: &TrojanConfig) -> ClientStream<S> {
        ClientStream {
            stream,
            state: ClientStreamWriteState::Connect(RequestHeader::UdpAssociate(svr_trojan_cfg.hash().clone())),
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }
}

impl<S> AsyncRead for ClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        this.stream.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for ClientStream<S>
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
