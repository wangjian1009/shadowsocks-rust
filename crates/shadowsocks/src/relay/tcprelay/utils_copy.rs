//! Utilities for TCP relay
//!
//! The `CopyBuffer`, `Copy` and `CopyBidirection` are borrowed from the [tokio](https://github.com/tokio-rs/tokio) project.
//! LICENSE MIT

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::ready;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::timeout::{TimeoutTicker, TimeoutWaiter};

const DEFAULT_BUF_SIZE: usize = 8 * 1024;

#[derive(Debug)]
struct CopyBuffer {
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
    idle_timeout: Option<TimeoutTicker>,
}

impl CopyBuffer {
    fn new(idle_timeout: Option<TimeoutTicker>) -> Self {
        Self {
            read_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; DEFAULT_BUF_SIZE].into_boxed_slice(),
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
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            // let check_timeout
            // let pinfut1 =  Pin::new(&mut fut1);

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
                    self.idle_timeout.as_ref().map(|o| o.tick());
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
#[must_use = "futures do nothing unless you `.await` or poll them"]
struct Copy<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
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

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done(u64),
}

impl TransferState {
    fn count(&self) -> u64 {
        match self {
            Self::Running(b) => b.amt,
            Self::ShuttingDown(c) => c.clone(),
            Self::Done(c) => c.clone(),
        }
    }
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
) -> Poll<io::Result<()>>
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
            TransferState::Done(_count) => return Poll::Ready(Ok(())),
        }
    }
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = (u64, u64, io::Result<()>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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
                return Poll::Ready((
                    a_to_b.count(),
                    b_to_a.count(),
                    Err(io::Error::new(io::ErrorKind::TimedOut, "copy bidirectional timeout")),
                ));
            }
        }

        let poll_a_to_b = transfer_one_direction(cx, a_to_b, a.as_mut(), b.as_mut());
        let poll_b_to_a = transfer_one_direction(cx, b_to_a, b.as_mut(), a.as_mut());

        // It is not a problem if ready! returns early because transfer_one_direction for the
        // other direction will keep returning TransferState::Done(count) in future calls to poll
        // let a_to_b = ready!(poll_a_to_b);
        // let b_to_a = ready!(poll_b_to_a);

        // Poll::Ready(Ok((a_to_b, b_to_a)))
        match (poll_a_to_b, poll_b_to_a) {
            (Poll::Pending, Poll::Pending) => Poll::Pending,
            (Poll::Ready(r), Poll::Pending) => Poll::Ready((a_to_b.count(), b_to_a.count(), r)),
            (Poll::Pending, Poll::Ready(r)) => Poll::Ready((a_to_b.count(), b_to_a.count(), r)),
            (Poll::Ready(a_r), Poll::Ready(b_r)) => {
                let r = if a_r.is_err() { a_r } else { b_r };
                Poll::Ready((a_to_b.count(), b_to_a.count(), r))
            }
        }
    }
}

pub async fn copy_bidirectional<E, P>(
    a: &mut E,
    b: &mut P,
    idle_timeout: Option<Duration>,
) -> (u64, u64, io::Result<()>)
where
    E: AsyncRead + AsyncWrite + Unpin + ?Sized,
    P: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let timeout_waiter = idle_timeout.map(|c| TimeoutWaiter::new(c));
    let timeout_ticker_a = timeout_waiter.as_ref().map(|o| o.ticker());
    let timeout_ticker_b = timeout_ticker_a.clone();

    CopyBidirectional {
        a,
        b,
        timeout_waiter,
        a_to_b: TransferState::Running(CopyBuffer::new(timeout_ticker_a)),
        b_to_a: TransferState::Running(CopyBuffer::new(timeout_ticker_b)),
    }
    .await
}
