use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Debug)]
pub(super) struct TransferBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl TransferBuffer {
    pub(super) fn new() -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; 4096].into_boxed_slice(),
        }
    }

    pub(super) fn poll_transfer<R, W, T>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        transfer_fn: &mut T,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
        T: Fn(&mut [u8]) -> io::Result<()>,
    {
        loop {
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);

                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        if self.need_flush {
                            ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }

                        return Poll::Pending;
                    }
                }

                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    transfer_fn(buf.filled_mut())?;
                    self.pos = 0;
                    self.cap = n;
                }
            }

            while self.pos < self.cap {
                let me = &mut *self;
                let i = ready!(writer.as_mut().poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.need_flush = true;
                }
            }

            debug_assert!(self.pos <= self.cap, "writer returned length larger than input slice");

            if self.pos == self.cap && self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
struct Transfer<'a, R: ?Sized, W: ?Sized, T: Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    transfer_fn: T,
    buf: TransferBuffer,
}

impl<R, W, T> Future for Transfer<'_, R, W, T>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
    T: (Fn(&mut [u8]) -> io::Result<()>) + Unpin,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let me = &mut *self;

        me.buf.poll_transfer(
            cx,
            Pin::new(&mut *me.reader),
            Pin::new(&mut *me.writer),
            &mut me.transfer_fn,
        )
    }
}

pub async fn transfer<'a, R, W, T>(reader: &'a mut R, writer: &'a mut W, transfer_fn: T) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
    T: (Fn(&mut [u8]) -> io::Result<()>) + Unpin,
{
    Transfer {
        reader,
        writer,
        transfer_fn,
        buf: TransferBuffer::new(),
    }
    .await
}
