//! TCP stream with rate limited
use std::{
    fmt::{self, Debug, Formatter},
    io::{self, IoSlice},
    num::NonZeroU32,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::{Duration, Instant},
};

use crate::net::Destination;

use super::super::StreamConnection;
use futures::Future;
use futures_timer::Delay;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use governor::{
    clock::MonotonicClock,
    state::{InMemoryState, NotKeyed},
    Jitter,
    NegativeMultiDecision,
    Quota,
};
use nonzero_ext::*;

type BaseRateLimiter = governor::RateLimiter<NotKeyed, InMemoryState, MonotonicClock>;

pub struct RateLimiter {
    pub(crate) limiter: BaseRateLimiter,
    pub(crate) max_burst: u32,
}

impl RateLimiter {
    pub fn new(quota: Quota) -> RateLimiter {
        let max_burst = quota.burst_size().get();
        let limiter = BaseRateLimiter::direct_with_clock(quota, &MonotonicClock::default());
        RateLimiter { limiter, max_burst }
    }
}

impl Debug for RateLimiter {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "RateLimiter: max-burst={}", self.max_burst)
    }
}

#[derive(PartialEq, Debug, Clone)]
enum State {
    ReadInner,
    CheckNextRead,
    Wait,
}

struct RateLimitedContext {
    limiter: Arc<RateLimiter>,
    delay: Delay,
    jitter: Jitter,
    state: State,
    readed: Option<NonZeroU32>,
}

pub struct RateLimitedStream<S> {
    stream: S,
    limiter_ctx: Option<RateLimitedContext>,
}

impl<S> RateLimitedStream<S> {
    #[inline]
    pub fn from_stream(stream: S, limiter: Option<Arc<RateLimiter>>) -> RateLimitedStream<S> {
        RateLimitedStream {
            stream,
            limiter_ctx: match limiter {
                Some(limiter) => Some(RateLimitedContext {
                    limiter,
                    delay: Delay::new(Duration::new(0, 0)),
                    jitter: Jitter::new(Duration::new(0, 0), Duration::new(0, 0)),
                    state: State::ReadInner,
                    readed: None,
                }),
                None => None,
            },
        }
    }
}

impl<S: StreamConnection> StreamConnection for RateLimitedStream<S> {
    #[inline]
    fn local_addr(&self) -> io::Result<Destination> {
        self.stream.local_addr()
    }

    #[inline]
    fn check_connected(&self) -> bool {
        self.stream.check_connected()
    }

    #[inline]
    fn set_rate_limit(&mut self, limiter: Option<Arc<RateLimiter>>) {
        match limiter {
            Some(limiter) => {
                self.limiter_ctx = Some(RateLimitedContext {
                    limiter,
                    delay: Delay::new(Duration::new(0, 0)),
                    jitter: Jitter::new(Duration::new(0, 0), Duration::new(0, 0)),
                    state: State::ReadInner,
                    readed: None,
                });
            }
            None => {
                self.limiter_ctx = None;
            }
        }
    }
}

impl<S> AsyncRead for RateLimitedStream<S>
where
    S: AsyncRead + Unpin,
{
    #[inline]
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.limiter_ctx.is_none() {
            let stream = Pin::new(&mut self.stream);
            return stream.poll_read(cx, buf);
        }

        loop {
            match self.limiter_ctx.as_ref().unwrap().state.clone() {
                State::ReadInner => {
                    let max_burst = self.limiter_ctx.as_ref().unwrap().limiter.max_burst;
                    let mut recv_buf = buf.take(max_burst as usize);
                    let stream = Pin::new(&mut self.stream);
                    match stream.poll_read(cx, &mut recv_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            let readed = recv_buf.filled().len();
                            unsafe { buf.assume_init(readed) };
                            buf.advance(readed);
                            if readed == 0 {
                                return Poll::Ready(Ok(()));
                            } else {
                                // log::error!("xxxxxxx: received {} data", buf.filled().len());
                                // 读取到数据进入CheckNextRead进行检测
                                let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                                limiter_ctx.state = State::CheckNextRead;
                                limiter_ctx.readed = Some((buf.filled().len() as u32).into_nonzero().unwrap());
                                continue;
                            }
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    }
                }
                State::CheckNextRead => {
                    let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                    let readed = limiter_ctx.readed.unwrap();
                    match limiter_ctx.limiter.limiter.check_n(readed) {
                        Err(err) => match err {
                            // 检测不通过，需要处理错误情况
                            NegativeMultiDecision::BatchNonConforming(_, negative) => {
                                // 需要等待一定时间，设置好定时器后尝试等待
                                let duration: Duration = negative.wait_time_from(Instant::now());
                                let duration = limiter_ctx.jitter + duration;
                                limiter_ctx.delay.reset(duration);
                                let future = Pin::new(&mut limiter_ctx.delay);
                                match future.poll(cx) {
                                    Poll::Pending => {
                                        // 定时器启动，进入等待状态，此时如果有数据，返回数据，等待只影响下一次读取
                                        limiter_ctx.state = State::Wait;
                                        if buf.filled().len() > 0 {
                                            // log::error!("xxxxxxx: sleep begin, duration={:?}, return {}", duration, buf.filled().len());
                                            return Poll::Ready(Ok(()));
                                        } else {
                                            // log::error!("xxxxxxx: sleep begin, duration={:?}, no data", duration);
                                            return Poll::Pending;
                                        }
                                    }
                                    Poll::Ready(_) => {
                                        // log::error!("xxxxxxx: sleep skip");
                                        // 定时器反馈无需等待，则再次检测(下一个循环还是CheckNextRead状态)
                                    }
                                }
                            }
                            NegativeMultiDecision::InsufficientCapacity(..) => {
                                // 读入的数据超过了最大读取数据，在读取时已经保护过，不应该再进入这个请客
                                unreachable!()
                            }
                        },
                        Ok(..) => {
                            // 检查通过，直接进入下一个循环读取数据
                            limiter_ctx.state = State::ReadInner;
                            limiter_ctx.readed = None;

                            if buf.filled().len() > 0 {
                                // 从State::ReadInner进入检测状态时，已经可能读取过数据，直接返回上层
                                // log::error!("xxxxxxx: check passed, return {}", buf.filled().len());
                                return Poll::Ready(Ok(()));
                            }

                            // 没有已经读取的数据，直接进行一次读取
                            // log::error!("xxxxxxx: check passed, no data");
                        }
                    }
                }
                State::Wait => {
                    let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                    let future = Pin::new(&mut limiter_ctx.delay);
                    match future.poll(cx) {
                        Poll::Pending => {
                            return Poll::Pending;
                        }
                        Poll::Ready(_) => {
                            limiter_ctx.state = State::CheckNextRead;
                        }
                    }
                }
            }
        }
    }
}

impl<S> AsyncWrite for RateLimitedStream<S>
where
    S: AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_write_vectored(cx, bufs)
    }
}

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(unix)] {
        use std::os::unix::io::{AsRawFd, RawFd};
        impl<S: AsRawFd> AsRawFd for RateLimitedStream<S> {
            fn as_raw_fd(&self) -> RawFd {
                self.stream.as_raw_fd()
            }
        }
    }
}
