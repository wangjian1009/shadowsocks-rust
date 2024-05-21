// Forked from tokio's copy.rs and copy_bidirectional.rs.
//
// Changes:
// - Customizable buffer size
// - Don't bother initializing buffer
// - Read and write whenever there's a space
// - Circular buffer

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::{transport::AsyncPing, util::allocate_vec};

const DEFAULT_BUF_SIZE: usize = 16384;

#[derive(Debug)]
struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    start_index: usize,
    cache_length: usize,
    size: usize,
    buf: Box<[u8]>,
}

impl CopyBuffer {
    pub fn new(size: usize, need_initial_flush: bool) -> Self {
        let buf = allocate_vec(size);
        Self {
            read_done: false,
            need_flush: need_initial_flush,
            need_write_ping: false,
            start_index: 0,
            cache_length: 0,
            size,
            buf: buf.into_boxed_slice(),
        }
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        writed: &mut u64,
        has_rw_data: &mut bool,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + AsyncWrite + AsyncPing + Unpin + ?Sized,
        W: AsyncRead + AsyncWrite + AsyncPing + Unpin + ?Sized,
    {
        loop {
            let mut read_pending = false;
            let mut write_pending = false;

            // Read as much as possible before writing. Some StreamConnection implementations
            // packetize each poll_write call individually, so this reduces the overhead.
            // Other StreamConnection implementations cache on poll_write, and
            // packetize/write to the stream on poll_flush - and this also ends up being
            // beneficial since we are calling poll_flush each external loop iteration.
            while !self.read_done && self.cache_length < self.size {
                let unused_start_index = (self.start_index + self.cache_length) % self.size;
                let unused_end_index_exclusive = if unused_start_index < self.start_index {
                    self.start_index
                } else {
                    self.size
                };

                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf[unused_start_index..unused_end_index_exclusive]);
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(val) => {
                        val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            *has_rw_data = true;
                            self.cache_length += n;
                        }
                    }
                    Poll::Pending => {
                        read_pending = true;
                        break;
                    }
                }
            }

            if self.need_write_ping {
                // if we just read data and we are going to write anyway, no need for a ping
                if self.cache_length == 0 {
                    match writer.as_mut().poll_write_ping(cx) {
                        Poll::Ready(val) => {
                            let written = val?;
                            self.need_write_ping = false;
                            if written {
                                self.need_flush = true;
                            }
                        }
                        Poll::Pending => {
                            write_pending = true;
                        }
                    }
                } else {
                    self.need_write_ping = false;
                }
            }

            // If our buffer has some data, let's write it out!
            // Loop and try to write out as much as possible to minimize forwarding
            // latency, and so that we increase the chance we have an optimal read
            // with start_index at zero.
            while self.cache_length > 0 {
                let used_start_index = self.start_index;
                let used_end_index_exclusive = std::cmp::min(self.start_index + self.cache_length, self.size);

                let me = &mut *self;
                match writer
                    .as_mut()
                    .poll_write(cx, &me.buf[used_start_index..used_end_index_exclusive])
                {
                    Poll::Ready(val) => {
                        let written = val?;
                        if written == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero byte into writer",
                            )));
                        } else {
                            *writed += written as u64;
                            *has_rw_data = true;
                            self.cache_length -= written;
                            if self.cache_length == 0 {
                                self.start_index = 0;
                            } else {
                                self.start_index = (self.start_index + written) % self.size;
                            }
                            self.need_flush = true;
                        }
                    }
                    Poll::Pending => {
                        write_pending = true;
                        break;
                    }
                }
            }

            if self.need_flush {
                ready!(writer.as_mut().poll_flush(cx))?;
                self.need_flush = false;
            }

            // If we've written all the data and we've seen EOF, finish the transfer.
            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(()));
            }

            // Previously we kept going until both read and write were pending, but
            // this might starve other tasks.
            if read_pending || write_pending {
                // If we got here,
                // 1) we hit read_pending on the current iteration.
                // 2) all data has been written successfully
                // 3) there is no data left to write and we need to read more.
                return Poll::Pending;
            }
        }
    }
}

enum TransferState {
    Running,
    ShuttingDown,
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopyBuffer,
    b_buf: CopyBuffer,
    a_to_b: TransferState,
    a_to_b_writed: u64,
    b_to_a: TransferState,
    b_to_a_writed: u64,
    ping_sleep_future: Option<Pin<Box<tokio::time::Sleep>>>,
    idle_timeout: Option<(Duration, Pin<Box<tokio::time::Sleep>>)>,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyBuffer,
    r: &mut A,
    w: &mut B,
    writed: &mut u64,
    has_rw_data: &mut bool,
) -> Poll<io::Result<()>>
where
    A: AsyncRead + AsyncWrite + AsyncPing + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + AsyncPing + Unpin + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut(), writed, has_rw_data))?;
                *state = TransferState::ShuttingDown;
            }
            TransferState::ShuttingDown => {
                ready!(w.as_mut().poll_shutdown(cx))?;
                *state = TransferState::Done;
            }
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + AsyncPing + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + AsyncPing + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_buf,
            b_buf,
            a_to_b,
            a_to_b_writed,
            b_to_a,
            b_to_a_writed,
            ping_sleep_future,
            idle_timeout,
        } = &mut *self;

        if let Some((_, ref mut idle_timeout_future)) = idle_timeout {
            let is_timeout = idle_timeout_future.as_mut().poll(cx).is_ready();
            if is_timeout {
                tracing::trace!("idle timeout reached");
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "copy bidirectional timeout",
                )));
            }
        }

        if let Some(ref mut sleep) = ping_sleep_future {
            let ping_fired = sleep.as_mut().poll(cx).is_ready();
            if ping_fired {
                // a_buf writes to b - so we need to check if b supports ping, and similarly
                // for b_buf.
                a_buf.need_write_ping = b.supports_ping();
                b_buf.need_write_ping = a.supports_ping();
                sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
            }
        }

        let mut has_rw_data = false;
        let a_to_b = transfer_one_direction(cx, a_to_b, &mut *a_buf, *a, *b, a_to_b_writed, &mut has_rw_data);
        let b_to_a = transfer_one_direction(cx, b_to_a, &mut *b_buf, *b, *a, b_to_a_writed, &mut has_rw_data);

        if let Some((timeout, ref mut idle_timeout_future)) = idle_timeout {
            if has_rw_data {
                tracing::trace!("XXXXXXX: resetting idle timeout");
                idle_timeout_future.as_mut().reset(tokio::time::Instant::now() + *timeout);
            }
        }

        if a_to_b.is_ready() {
            return a_to_b.map_ok(|_| (*a_to_b_writed, *b_to_a_writed));
        } else if b_to_a.is_ready() {
            return b_to_a.map_ok(|_| (*a_to_b_writed, *b_to_a_writed));
        }

        Poll::Pending
    }
}

/// Copies data in both directions between `a` and `b`.
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
/// it will return a tuple of the number of bytes copied from a to b
/// and the number of bytes copied from b to a, in that order.
///
/// [`shutdown()`]: crate::io::AsyncWriteExt::shutdown
///
/// # Errors
///
/// The future will immediately return an error if any IO operation on `a`
/// or `b` returns an error. Some data read from either stream may be lost (not
/// written to the other stream) in this case.
///
/// # Return value
///
/// Returns a tuple of bytes copied `a` to `b` and bytes copied `b` to `a`.
pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Option<Duration>,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
) -> Result<(u64, u64), std::io::Error>
where
    A: AsyncRead + AsyncWrite + AsyncPing + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + AsyncPing + Unpin + ?Sized,
{
    let idle_timeout = idle_timeout.map(|d| (d, Box::pin(tokio::time::sleep(d))));

    let ping_sleep_future = if a.supports_ping() || b.supports_ping() {
        Some(Box::pin(tokio::time::sleep(std::time::Duration::from_secs(60))))
    } else {
        None
    };

    CopyBidirectional {
        a,
        b,
        // this is correctly reversed - CopyBuffer will copy from a (reader) to b (writer) using
        // a_buf, which means that the need_flush signal is for the writer (b), and vice versa for
        // b_buf.
        a_buf: CopyBuffer::new(DEFAULT_BUF_SIZE, b_need_initial_flush),
        b_buf: CopyBuffer::new(DEFAULT_BUF_SIZE, a_need_initial_flush),
        a_to_b: TransferState::Running,
        a_to_b_writed: 0,
        b_to_a: TransferState::Running,
        b_to_a_writed: 0,
        ping_sleep_future,
        idle_timeout,
    }
    .await
}
