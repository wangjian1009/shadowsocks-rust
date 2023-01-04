use std::{
    io,
    io::Cursor,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{ready, Future};
use spin::Mutex as SpinMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time,
};

use crate::{
    config::ServerConfig,
    net::ConnectOpts,
    transport::{Connector, DeviceOrGuard, StreamConnection},
    vless::{new_error, Config},
    ServerAddr,
};

use super::{encoding, protocol};

enum ClientStreamWriteState {
    Connect {
        request: protocol::RequestHeader,
        addons: Option<protocol::Addons>,
    },
    Connecting(SpinMutex<BytesMut>),
    Connected,
}

enum ClientStreamReadState {
    Init,
    Connecting(SpinMutex<Vec<u8>>),
    ReadingFromCache(SpinMutex<Vec<u8>>),
    Connected,
}

/// A stream for sending / receiving data stream from remote server via vless' proxy server
pub struct ClientStream<S> {
    stream: S,
    write_state: Arc<ClientStreamWriteState>,
    read_state: Arc<ClientStreamReadState>,
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
        svr_vless_cfg: &Config,
        command: protocol::RequestCommand,
        target_address: Option<ServerAddr>,
        opts: &ConnectOpts,
        map_fn: F,
    ) -> io::Result<ClientStream<S>>
    where
        C: Connector,
        F: FnOnce(C::TS) -> S,
    {
        let stream = match time::timeout(svr_cfg.timeout(), connector.connect(svr_cfg.external_addr(), opts)).await {
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
            svr_cfg.external_addr(),
            svr_cfg.acceptor_transport_tag(),
            opts
        );

        let request = protocol::RequestHeader {
            version: 0,
            user: Self::pick_user(svr_vless_cfg)?.account.id.clone(),
            command,
            address: target_address.map(protocol::Address::from),
        };

        Ok(ClientStream::new(map_fn(stream), request))
    }

    #[inline]
    fn new(stream: S, request: protocol::RequestHeader) -> ClientStream<S> {
        ClientStream {
            stream,
            write_state: Arc::new(ClientStreamWriteState::Connect { request, addons: None }),
            read_state: Arc::new(ClientStreamReadState::Init),
        }
    }

    #[inline]
    fn pick_user(cfg: &Config) -> io::Result<&protocol::User> {
        match cfg.clients.len() {
            0 => Err(io::Error::new(io::ErrorKind::Other, "no user configured")),
            1 => Ok(&cfg.clients[0]),
            _ => {
                let idx: u16 = rand::random();
                Ok(&cfg.clients[(idx % cfg.clients.len() as u16) as usize])
            }
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }
}

impl<S> ClientStream<S> {
    fn process_response(&mut self, addon: Option<protocol::Addons>) -> io::Result<()> {
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
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.read_state.clone().as_ref() {
                ClientStreamReadState::Init => {
                    if let Err(err) = {
                        let stream = Pin::new(&mut self.stream);
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
                            self.read_state = Arc::new(ClientStreamReadState::Connecting(SpinMutex::new(buffer)));
                        }
                        Poll::Ready(r) => match r {
                            Err(err) => return Poll::Ready(Err(err)),
                            Ok(addon) => match self.process_response(addon) {
                                Err(err) => return Poll::Ready(Err(err)),
                                Ok(()) => {
                                    self.read_state = Arc::new(ClientStreamReadState::Connected);

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
                                        return Poll::Ready(Ok(()));
                                    }
                                }
                            },
                        },
                    }
                }
                ClientStreamReadState::Connecting(buffer) => {
                    match {
                        let stream = Pin::new(&mut self.stream);
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
                    let mut buffer = buffer.lock();
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
                        Ok(addon) => match self.process_response(addon) {
                            Err(err) => return Poll::Ready(Err(err)),
                            Ok(()) => {
                                let used = cursor.position() as usize;
                                if total == used {
                                    // 所有数据都已经处理掉了，则直接进入Connected状态
                                    self.read_state = Arc::new(ClientStreamReadState::Connected);
                                } else {
                                    // 只处理掉了部分数据，则清理掉已经读取的部分，然后进入Read状态，并返回调用者处理
                                    self.read_state = Arc::new(ClientStreamReadState::ReadingFromCache(
                                        SpinMutex::new(buffer[used..total].to_owned()),
                                    ));
                                }
                            }
                        },
                    }
                }
                ClientStreamReadState::ReadingFromCache(buffer) => {
                    let mut buffer = buffer.lock();

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
                        self.read_state = Arc::new(ClientStreamReadState::Connected);
                    }
                    return Poll::Ready(Ok(()));
                }
                ClientStreamReadState::Connected => {
                    let stream = Pin::new(&mut self.stream);
                    return stream.poll_read(cx, buf);
                }
            }
        }
    }
}

impl<S> AsyncWrite for ClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        loop {
            match self.write_state.clone().as_ref() {
                ClientStreamWriteState::Connect { request, addons } => {
                    let request_length = encoding::request_header_serialized_len(request, addons);

                    let mut buffer = BytesMut::with_capacity(request_length);
                    encoding::encode_request_header(&mut buffer, request, addons)?;

                    self.write_state = Arc::new(ClientStreamWriteState::Connecting(SpinMutex::new(buffer)));
                }
                ClientStreamWriteState::Connecting(buffer) => {
                    let stream = Pin::new(&mut self.stream);
                    let mut buffer = buffer.lock();
                    let n = ready!(stream.poll_write(cx, buffer.as_mut()))?;
                    if n == buffer.len() {
                        self.write_state = Arc::new(ClientStreamWriteState::Connected);
                    } else {
                        buffer.advance(n);
                    }
                }
                ClientStreamWriteState::Connected => {
                    let stream = Pin::new(&mut self.stream);
                    return stream.poll_write(cx, buf);
                }
            }
        }
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_shutdown(cx)
    }
}
