use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use futures::{ready, FutureExt};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, OwnedMutexGuard},
};

use crate::{
    transport::{DeviceOrGuard, StreamConnection},
    vless::new_error,
};

use super::{
    frame::{encode_frame, encode_frame_and_data_len, FrameMetadata, FrameOption, SessionStatus},
    session::{Session, SessionReadCmd},
};

#[derive(Clone)]
enum MuxStreamReadState {
    Waiting,
    Reading(usize),
    ReadDone,
    Closed,
}

#[derive(Clone)]
enum MuxStreamWriteState {
    Waiting,
    NotConnected,
    WritingMeta {
        guard: Arc<OwnedMutexGuard<()>>,
        meta: Arc<Vec<u8>>,
        meta_writed: usize,
        data_len: usize,
    },
    WritingData {
        guard: Arc<OwnedMutexGuard<()>>,
        data_len: usize,
        data_writed: usize,
    },
}

pub struct MuxStream {
    session: Arc<Session>,
    read_state: MuxStreamReadState,
    read_cmd_receiver: mpsc::Receiver<SessionReadCmd>,
    write_state: MuxStreamWriteState,
}

impl MuxStream {
    pub fn new(session: Arc<Session>, read_cmd_receiver: mpsc::Receiver<SessionReadCmd>) -> Self {
        Self {
            session,
            read_state: MuxStreamReadState::Waiting,
            read_cmd_receiver,
            write_state: MuxStreamWriteState::Waiting,
        }
    }

    pub fn connect(session: Arc<Session>, read_cmd_receiver: mpsc::Receiver<SessionReadCmd>) -> io::Result<Self> {
        Ok(Self {
            session,
            read_state: MuxStreamReadState::Waiting,
            read_cmd_receiver,
            write_state: MuxStreamWriteState::NotConnected,
        })
    }

    pub fn session(&self) -> &Session {
        self.session.as_ref()
    }
}

impl StreamConnection for MuxStream {
    fn check_connected(&self) -> bool {
        unreachable!()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, _rate_limit: Option<Arc<crate::transport::RateLimiter>>) {
        unreachable!()
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        unreachable!()
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.read_state.clone() {
                MuxStreamReadState::Reading(sz) => {
                    let read_sz = std::cmp::min(sz, buf.capacity());
                    match {
                        let read_stream = self.session.context().base_stream();
                        tokio::pin!(read_stream);
                        ready!(read_stream.poll_read(cx, &mut buf.take(read_sz)))
                    } {
                        Ok(()) => {
                            if read_sz == sz {
                                // 读取完成，尝试通知完成
                                let poll_r = self.session.read_done_sender().send(()).boxed().poll_unpin(cx);
                                match poll_r {
                                    Poll::Pending => self.read_state = MuxStreamReadState::ReadDone,
                                    Poll::Ready(Ok(())) => self.read_state = MuxStreamReadState::Waiting,
                                    Poll::Ready(Err(err)) => return Poll::Ready(Err(new_error(err))),
                                }
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }
                MuxStreamReadState::Waiting => {
                    let cmd = ready!(self.read_cmd_receiver.recv().boxed().poll_unpin(cx));
                    match cmd {
                        None => {
                            log::error!("#{}: recv cmd none", self.session.meta());
                        }
                        Some(SessionReadCmd::Close) => {
                            log::info!("#{}: recv read closed", self.session.meta());
                            self.read_state = MuxStreamReadState::Closed;
                            return Poll::Ready(Ok(()));
                        }
                        Some(SessionReadCmd::Read(sz)) => {
                            log::info!("#{}: recv {} data", self.session.meta(), sz);
                            if sz > 0 {
                                self.read_state = MuxStreamReadState::Reading(sz);
                            }
                        }
                    }
                }
                MuxStreamReadState::ReadDone => {
                    let poll_r = self.session.read_done_sender().send(()).boxed().poll_unpin(cx);
                    match poll_r {
                        Poll::Pending => {}
                        Poll::Ready(Ok(())) => self.read_state = MuxStreamReadState::Waiting,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(new_error(err))),
                    }
                }
                MuxStreamReadState::Closed => {
                    log::error!("#{}: read aflter closed", self.session.meta());
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("read in closed"),
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for MuxStream {
    #[inline]
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            match self.write_state.clone() {
                MuxStreamWriteState::Waiting => {
                    let guard = ready!(self.session.context().write_lock().lock_owned().boxed().poll_unpin(cx));

                    let mut frame = FrameMetadata {
                        session_id: self.session.meta().id,
                        option: 0,
                        session_status: SessionStatus::Keep,
                        target: None,
                    };

                    let mut buf = Vec::new();

                    let data_len = std::cmp::max(u16::MAX as usize, buf.len());
                    if data_len > 0 {
                        FrameOption::Data.set_to(&mut frame.option);
                        encode_frame_and_data_len(&mut buf, &frame, data_len as u16)?;
                    } else {
                        encode_frame(&mut buf, &frame)?;
                    }

                    self.write_state = MuxStreamWriteState::WritingMeta {
                        guard: Arc::new(guard),
                        meta: Arc::new(buf),
                        meta_writed: 0,
                        data_len,
                    };
                }
                MuxStreamWriteState::NotConnected => {
                    let guard = ready!(self.session.context().write_lock().lock_owned().boxed().poll_unpin(cx));

                    let mut frame = FrameMetadata {
                        session_id: self.session.meta().id,
                        option: 0,
                        session_status: SessionStatus::New,
                        target: Some(self.session.meta().target_addr.clone()),
                    };

                    let mut buf = Vec::new();

                    let data_len = std::cmp::max(u16::MAX as usize, buf.len());
                    if data_len > 0 {
                        FrameOption::Data.set_to(&mut frame.option);
                        encode_frame_and_data_len(&mut buf, &frame, data_len as u16)?;
                    } else {
                        encode_frame(&mut buf, &frame)?;
                    }

                    self.write_state = MuxStreamWriteState::WritingMeta {
                        guard: Arc::new(guard),
                        meta: Arc::new(buf),
                        meta_writed: 0,
                        data_len,
                    };
                }
                MuxStreamWriteState::WritingMeta {
                    meta,
                    meta_writed,
                    guard,
                    data_len,
                } => {
                    match {
                        let write_stream = self.session.context().base_stream();
                        tokio::pin!(write_stream);
                        ready!(write_stream.poll_write(cx, &meta[meta_writed..]))
                    } {
                        Ok(once_writed) => {
                            let meta_writed = meta_writed + once_writed;
                            if meta_writed == meta.len() {
                                if data_len > 0 {
                                    self.write_state = MuxStreamWriteState::WritingData {
                                        guard,
                                        data_len,
                                        data_writed: 0,
                                    };
                                } else {
                                    self.write_state = MuxStreamWriteState::Waiting;
                                }
                            } else {
                                self.write_state = MuxStreamWriteState::WritingMeta {
                                    guard,
                                    meta,
                                    meta_writed,
                                    data_len,
                                };
                            }
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }
                MuxStreamWriteState::WritingData {
                    guard,
                    data_len,
                    data_writed,
                } => {
                    match {
                        let write_stream = self.session.context().base_stream();
                        tokio::pin!(write_stream);
                        ready!(write_stream.poll_write(cx, &buf[data_writed..data_len]))
                    } {
                        Ok(once_writed) => {
                            let data_writed = data_writed + once_writed;
                            if data_writed == data_len {
                                self.write_state = MuxStreamWriteState::Waiting;
                            } else {
                                self.write_state = MuxStreamWriteState::WritingData {
                                    guard,
                                    data_len,
                                    data_writed,
                                }
                            }
                            return Poll::Ready(Ok(data_len));
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }
            }
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
