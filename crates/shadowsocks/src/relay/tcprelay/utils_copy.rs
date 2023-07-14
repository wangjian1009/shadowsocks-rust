//! Utilities for TCP relay
//!
//! The `CopyBuffer`, `Copy` and `CopyBidirection` are borrowed from the [tokio](https://github.com/tokio-rs/tokio) project.
//! LICENSE MIT

use std::{
    fmt::{self, Debug},
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use crate::timeout::{TimeoutTicker, TimeoutWaiter};
use futures::ready;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

const DEFAULT_BUF_SIZE: usize = 8 * 1024;

struct CopyBuffer {
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
    idle_timeout: Option<TimeoutTicker>,
}

impl Debug for CopyBuffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CopyBuffer")
            .field("read_done", &self.read_done)
            .field("pos", &self.pos)
            .field("cap", &self.cap)
            .field("amt", &self.amt)
            .finish_non_exhaustive()
    }
}

impl CopyBuffer {
    fn new(buffer_size: usize, idle_timeout: Option<TimeoutTicker>) -> Self {
        Self {
            read_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; buffer_size].into_boxed_slice(),
            idle_timeout,
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                ready!(reader.as_mut().poll_read(cx, &mut buf))?;
                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                    if let Some(o) = self.idle_timeout.as_ref() {
                        o.tick();
                    }
                }
            }

            // If our buffer has some data, let's write it out!
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
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

/// A future that asynchronously copies the entire contents of a reader into a
/// writer.
#[derive(Debug)]
#[pin_project]
#[must_use = "futures do nothing unless you `.await` or poll them"]
struct Copy<'a, R: ?Sized, W: ?Sized> {
    #[pin]
    reader: &'a mut R,
    #[pin]
    writer: &'a mut W,
    buf: CopyBuffer,
}

impl<R, W> Future for Copy<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let me = &mut *self;

        me.buf
            .poll_copy(cx, Pin::new(&mut *me.reader), Pin::new(&mut *me.writer))
    }
}

#[derive(Debug)]
enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done(u64),
}

#[pin_project(project = CopyBidirectionalProj)]
struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    #[pin]
    a: &'a mut A,
    #[pin]
    b: &'a mut B,
    #[pin]
    timeout_waiter: Option<TimeoutWaiter>,
    a_to_b: TransferState,
    b_to_a: TransferState,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    mut r: Pin<&mut A>,
    mut w: Pin<&mut B>,
) -> Poll<io::Result<u64>>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    loop {
        match state {
            TransferState::Running(buf) => {
                let count = ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown(count);
            }
            TransferState::ShuttingDown(count) => {
                ready!(w.as_mut().poll_shutdown(cx))?;
                *state = TransferState::Done(*count);
            }
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

impl<A, B> CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    #[inline(always)]
    fn poll_impl(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<(u64, u64)>> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectionalProj {
            mut a,
            mut b,
            timeout_waiter,
            a_to_b,
            b_to_a,
        } = self.project();

        if let Some(timeout_waiter) = timeout_waiter.as_pin_mut() {
            if timeout_waiter.poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "copy bidirectional timeout",
                )));
            }
        }

        let poll_a_to_b = transfer_one_direction(cx, a_to_b, a.as_mut(), b.as_mut())?;
        let poll_b_to_a = transfer_one_direction(cx, b_to_a, b.as_mut(), a.as_mut())?;

        // It is not a problem if ready! returns early because transfer_one_direction for the
        // other direction will keep returning TransferState::Done(count) in future calls to poll
        let a_to_b = ready!(poll_a_to_b);
        let b_to_a = ready!(poll_b_to_a);

        Poll::Ready(Ok((a_to_b, b_to_a)))
    }
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().poll_impl(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(r) => {
                match r {
                    Ok(..) => {
                        trace!(
                            "copy bidirection ends, a_to_b: {:?}, b_to_a: {:?}",
                            self.a_to_b,
                            self.b_to_a
                        );
                    }
                    Err(ref err) => {
                        debug!(
                            "copy bidirection ends with error: {}, a_to_b: {:?}, b_to_a: {:?}",
                            err, self.a_to_b, self.b_to_a
                        );
                    }
                }
                Poll::Ready(r)
            }
        }
    }
}

/// Copies data in both directions
///
/// This function returns a future that will read from both streams,
/// writing any data read to the opposing stream.
/// This happens in both directions concurrently.
///
/// If an EOF is observed on one stream, [`shutdown()`] will be invoked on
/// the other, and reading from that stream will stop. Copying of data in
/// the other direction will continue.
///
/// The future will complete successfully once both directions of communication has been shut down.
/// A direction is shut down when the reader reports EOF,
/// at which point [`shutdown()`] is called on the corresponding writer. When finished,
/// it will return a tuple of the number of bytes copied from encrypted to plain
/// and the number of bytes copied from plain to encrypted, in that order.
///
/// [`shutdown()`]: tokio::io::AsyncWriteExt::shutdown
///
/// # Errors
///
/// The future will immediately return an error if any IO operation any of the streams
/// returns an error. Some data read from either stream may be lost (not
/// written to the other stream) in this case.
///
/// # Return value
///
/// Returns a tuple of bytes copied on both directions
pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B, idle_timeout: Option<Duration>) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let timeout_waiter = idle_timeout.map(TimeoutWaiter::new);
    let timeout_ticker_a = timeout_waiter.as_ref().map(|o| o.ticker());
    let timeout_ticker_b = timeout_ticker_a.clone();

    CopyBidirectional {
        a,
        b,
        timeout_waiter,
        a_to_b: TransferState::Running(CopyBuffer::new(DEFAULT_BUF_SIZE, timeout_ticker_a)),
        b_to_a: TransferState::Running(CopyBuffer::new(DEFAULT_BUF_SIZE, timeout_ticker_b)),
    }
    .await
}
