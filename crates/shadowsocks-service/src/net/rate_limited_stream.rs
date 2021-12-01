//! TCP stream with rate limited
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    num::NonZeroU32,
    pin::Pin,
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures::Future;
use futures_timer::Delay;
use shadowsocks::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use governor::{
    clock::MonotonicClock,
    state::{InMemoryState, NotKeyed},
    Jitter,
    NegativeMultiDecision,
    Quota,
};
use nonzero_ext::*;

type RateLimiter = governor::RateLimiter<NotKeyed, InMemoryState, MonotonicClock>;

#[derive(PartialEq, Debug, Clone)]
enum State {
    ReadInner,
    CheckNextRead,
    Wait,
}

struct RateLimitedContext {
    limiter: RateLimiter,
    max_burst: u32,
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
    pub fn from_stream(stream: S, quota: Option<Quota>) -> RateLimitedStream<S> {
        RateLimitedStream {
            stream,
            limiter_ctx: match quota {
                Some(quota) => {
                    let max_burst = quota.burst_size().get();
                    let limiter = RateLimiter::direct_with_clock(quota, &MonotonicClock::default());
                    Some(RateLimitedContext {
                        limiter,
                        max_burst,
                        delay: Delay::new(Duration::new(0, 0)),
                        jitter: Jitter::new(Duration::new(0, 0), Duration::new(0, 0)),
                        state: State::ReadInner,
                        readed: None,
                    })
                }
                None => None,
            },
        }
    }

    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
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
                    let max_burst = self.limiter_ctx.as_ref().unwrap().max_burst;
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
                                // 读取到数据直接返回，等待用于延迟下一次读取
                                let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                                limiter_ctx.state = State::CheckNextRead;
                                limiter_ctx.readed = Some((buf.filled().len() as u32).into_nonzero().unwrap());
                                return Poll::Ready(Ok(()));
                            }
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    }
                }
                State::CheckNextRead => {
                    let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                    let readed = limiter_ctx.readed.unwrap();
                    match limiter_ctx.limiter.check_n(readed) {
                        Err(err) => match err {
                            NegativeMultiDecision::BatchNonConforming(_, negative) => {
                                // 需要等待一定时间
                                let duration: Duration = negative.wait_time_from(Instant::now());
                                let duration = limiter_ctx.jitter + duration;
                                limiter_ctx.delay.reset(duration);
                                let future = Pin::new(&mut limiter_ctx.delay);
                                match future.poll(cx) {
                                    Poll::Pending => {
                                        // 定时器启动，进入等待状态
                                        limiter_ctx.state = State::Wait;
                                        return Poll::Pending;
                                    }
                                    Poll::Ready(_) => {
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

pub type RateLimitedTcpStream = RateLimitedStream<TcpStream>;

impl RateLimitedTcpStream {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().local_addr()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().peer_addr()
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        self.get_ref().nodelay()
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.get_ref().set_nodelay(nodelay)
    }
}
