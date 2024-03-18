use std::{
    io,
    io::Cursor,
    pin::Pin,
    task::{self, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{ready, Future};
use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time,
};

use crate::{
    config::ServerConfig,
    net::ConnectOpts,
    transport::{Connector, DeviceOrGuard, StreamConnection},
};

use super::{encoding, new_error, protocol, UUID, Address};

#[derive(Clone, Debug, PartialEq)]
pub struct ClientConfig {
    pub user_id: UUID,
}

enum ClientStreamWriteState {
    Connect {
        request: protocol::RequestHeader,
        addons: Option<protocol::Addons>,
    },
    Connecting(BytesMut),
    Connected,
}

enum ClientStreamReadState {
    Init,
    Connecting(Vec<u8>),
    ReadingFromCache(Vec<u8>),
    Connected,
}

/// A stream for sending / receiving data stream from remote server via vless' proxy server
#[pin_project(project = ClientStreamProj)]
pub struct ClientStream<S> {
    stream: S,
    write_state: ClientStreamWriteState,
    read_state: ClientStreamReadState,
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
    /// Connect to target `addr` via vless' server configured by `svr_cfg`, maps `TcpStream` to customized stream with `map_fn`
    pub async fn connect<C, F>(
        connector: &C,
        svr_cfg: &ServerConfig,
        svr_vless_cfg: &ClientConfig,
        command: protocol::RequestCommand,
        target_address: Address,
        opts: &ConnectOpts,
        map_fn: F,
    ) -> io::Result<ClientStream<S>>
    where
        C: Connector,
        F: FnOnce(C::TS) -> S,
    {
        let stream = match time::timeout(svr_cfg.timeout(), connector.connect(svr_cfg.tcp_external_addr(), opts)).await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e),
            Err(..) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect {} timeout", svr_cfg.addr()),
                ))
            }
        };

        tracing::trace!(
            "connected vless {} remote {}{} (outbound: {}) with {:?}",
            command,
            svr_cfg.addr(),
            svr_cfg.tcp_external_addr(),
            svr_cfg.acceptor_transport_tag(),
            opts
        );

        Ok(Self::new(
            map_fn(stream),
            svr_vless_cfg.user_id.clone(),
            command,
            target_address,
        ))
    }

    #[inline]
    pub fn new(stream: S, user: UUID, command: protocol::RequestCommand, address: Address) -> Self {
        let request = protocol::RequestHeader {
            version: 0,
            user,
            command,
            address,
        };

        ClientStream {
            stream,
            write_state: ClientStreamWriteState::Connect { request, addons: None },
            read_state: ClientStreamReadState::Init,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }
}

impl<S> ClientStream<S> {
    fn process_response(addon: Option<protocol::Addons>) -> io::Result<()> {
        if addon.is_some() {
            return Err(new_error("decode rquest: not support addon"));
        }
        Ok(())
    }
}

impl<S> AsyncRead for ClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let ClientStreamProj {
            mut stream,
            mut read_state,
            ..
        } = self.project();

        loop {
            let mut next_state = None;
            let mut is_done = false;

            match &mut read_state {
                ClientStreamReadState::Init => {
                    if let Err(err) = {
                        let stream = Pin::new(&mut stream);
                        ready!(stream.poll_read(cx, buf))
                    } {
                        return Poll::Ready(Err(err));
                    };

                    // 连接已经关闭，则返回
                    if buf.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }

                    // 读取响应
                    let total = buf.filled().len();
                    let mut cursor = Cursor::new(buf.filled());
                    let poll_result = {
                        let decode_op = encoding::decode_response_header(&mut cursor);
                        tokio::pin!(decode_op);
                        decode_op.poll(cx)
                    };

                    match poll_result {
                        Poll::Pending => {
                            // 数据不够，保持数据等待后续数据到来
                            let buffer = buf.filled().to_owned();
                            buf.set_filled(0);
                            next_state = Some(ClientStreamReadState::Connecting(buffer));
                        }
                        Poll::Ready(r) => match r {
                            Err(err) => return Poll::Ready(Err(err)),
                            Ok(addon) => match Self::process_response(addon) {
                                Err(err) => return Poll::Ready(Err(err)),
                                Ok(()) => {
                                    next_state = Some(ClientStreamReadState::Connected);

                                    let used = cursor.position() as usize;
                                    assert!(used <= total);
                                    let left = total - used;
                                    if left == 0 {
                                        // 所有数据都已经处理掉了，则直接进入Connected状态
                                        buf.clear();
                                    } else {
                                        // 只处理掉了部分数据，则清理掉已经读取的部分，然后进入Connected状态，并返回调用者处理
                                        buf.filled_mut().copy_within(used.., 0);
                                        buf.set_filled(left);
                                        is_done = true;
                                    }
                                }
                            },
                        },
                    }
                }
                ClientStreamReadState::Connecting(ref mut buffer) => {
                    match {
                        let stream = Pin::new(&mut stream);
                        ready!(stream.poll_read(cx, buf))
                    } {
                        Ok(()) => {}
                        Err(err) => return Poll::Ready(Err(err)),
                    }

                    // 连接已经关闭，则返回
                    if buf.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }

                    // 拼接数据
                    buffer.extend_from_slice(buf.filled());
                    buf.clear();

                    // 读取响应
                    let total = buffer.len();
                    let mut cursor = Cursor::new(buffer.as_mut_slice());
                    let poll_result = {
                        let decode_op = encoding::decode_response_header(&mut cursor);
                        tokio::pin!(decode_op);
                        ready!(decode_op.poll(cx))
                    };

                    match poll_result {
                        Err(err) => return Poll::Ready(Err(err)),
                        Ok(addon) => match Self::process_response(addon) {
                            Err(err) => return Poll::Ready(Err(err)),
                            Ok(()) => {
                                let used = cursor.position() as usize;
                                if total == used {
                                    // 所有数据都已经处理掉了，则直接进入Connected状态
                                    next_state = Some(ClientStreamReadState::Connected);
                                } else {
                                    // 只处理掉了部分数据，则清理掉已经读取的部分，然后进入Read状态，并返回调用者处理
                                    next_state =
                                        Some(ClientStreamReadState::ReadingFromCache(buffer[used..total].to_owned()));
                                }
                            }
                        },
                    }
                }
                ClientStreamReadState::ReadingFromCache(ref mut buffer) => {
                    assert!(buffer.len() > 0);
                    let read_size = std::cmp::min(buffer.len(), buf.remaining());
                    if buffer.len() <= buf.capacity() {
                        buf.initialize_unfilled_to(read_size)
                            .copy_from_slice(&buffer[..read_size]);
                    }

                    let left_size = buffer.len() - read_size;
                    if left_size > 0 {
                        // 读取后还有剩余数据
                        buffer.copy_within(read_size.., 0);
                        unsafe { buffer.set_len(left_size) };
                    } else {
                        // 读取后所有数据都已经获取
                        next_state = Some(ClientStreamReadState::Connected);
                    }

                    is_done = true;
                }
                ClientStreamReadState::Connected => {
                    let stream = Pin::new(&mut stream);
                    return stream.poll_read(cx, buf);
                }
            }

            if next_state.is_some() {
                *read_state = next_state.take().unwrap();
            }

            if is_done {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S> AsyncWrite for ClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let ClientStreamProj {
            mut stream,
            mut write_state,
            ..
        } = self.project();

        loop {
            let mut next_state = None;

            match &mut write_state {
                ClientStreamWriteState::Connect { request, addons } => {
                    let request_length = encoding::request_header_serialized_len(request, addons);

                    let mut buffer = BytesMut::with_capacity(request_length);
                    encoding::encode_request_header(&mut buffer, request, addons)?;

                    next_state = Some(ClientStreamWriteState::Connecting(buffer));
                }
                ClientStreamWriteState::Connecting(buffer) => {
                    let stream = Pin::new(&mut stream);
                    let n = ready!(stream.poll_write(cx, buffer.as_mut()))?;
                    if n == buffer.len() {
                        next_state = Some(ClientStreamWriteState::Connected);
                    } else {
                        buffer.advance(n);
                    }
                }
                ClientStreamWriteState::Connected => {
                    let stream = Pin::new(&mut stream);
                    return stream.poll_write(cx, buf);
                }
            }

            if next_state.is_some() {
                *write_state = next_state.take().unwrap();
            }
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        let ClientStreamProj { mut stream, .. } = self.project();
        let stream = Pin::new(&mut stream);
        stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        let ClientStreamProj { mut stream, .. } = self.project();
        let stream = Pin::new(&mut stream);
        stream.poll_shutdown(cx)
    }
}
