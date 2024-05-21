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

use futures::Future;
use futures_core::ready;
use futures_timer::Delay;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use governor::{
    clock::MonotonicClock,
    state::{InMemoryState, NotKeyed},
    Jitter, Quota,
};
use nonzero_ext::*;

use crate::transport::AsyncPing;

use super::{
    super::{DeviceOrGuard, StreamConnection},
    BoundWidth,
};

type BaseRateLimiter = governor::RateLimiter<NotKeyed, InMemoryState, MonotonicClock>;

struct RateLimiterData {
    rate_limit: BoundWidth,
    limiter: BaseRateLimiter,
}

impl RateLimiterData {
    fn new(rate_limit: BoundWidth) -> io::Result<Self> {
        let byte_per_second = rate_limit.as_bps() / 8u32;

        if byte_per_second == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "BoundWith too small"));
        }

        let limiter = BaseRateLimiter::direct_with_clock(
            Quota::per_second(byte_per_second.into_nonzero().unwrap()),
            &MonotonicClock::default(),
        );
        Ok(Self { limiter, rate_limit })
    }
}

pub struct RateLimiter {
    data: spin::Mutex<Option<RateLimiterData>>,
}

/// see governor::NegativeMultiDecision
pub enum NegativeMultiDecision {
    BatchNonConforming(Duration),
    InsufficientCapacity,
}

impl RateLimiter {
    pub fn new(rate_limit: Option<BoundWidth>) -> io::Result<RateLimiter> {
        let data = match rate_limit {
            Some(rate_limit) => Some(RateLimiterData::new(rate_limit)?),
            None => None,
        };

        Ok(RateLimiter {
            data: spin::Mutex::new(data),
        })
    }

    pub fn set_rate_limit(&self, rate_limit: Option<BoundWidth>) -> io::Result<()> {
        let data = match rate_limit {
            Some(rate_limit) => Some(RateLimiterData::new(rate_limit)?),
            None => None,
        };

        *self.data.lock() = data;

        Ok(())
    }

    pub fn rate_limit(&self) -> Option<BoundWidth> {
        let data = self.data.lock();
        data.as_ref().map(|data| data.rate_limit.clone())
    }

    pub fn check_n(&self, n: NonZeroU32) -> Result<(), NegativeMultiDecision> {
        let data = self.data.lock();
        match data.as_ref() {
            Some(data) => match data.limiter.check_n(n) {
                Err(err) => match err {
                    governor::NegativeMultiDecision::BatchNonConforming(_, negative) => {
                        let duration: Duration = negative.wait_time_from(Instant::now());
                        Err(NegativeMultiDecision::BatchNonConforming(duration))
                    }
                    governor::NegativeMultiDecision::InsufficientCapacity(..) => {
                        Err(NegativeMultiDecision::InsufficientCapacity)
                    }
                },
                Ok(..) => Ok(()),
            },
            None => Ok(()),
        }
    }

    pub fn max_receive_once(&self) -> Option<usize> {
        let data = self.data.lock();
        match data.as_ref() {
            Some(data) => {
                let bytes_per_10ms = data.rate_limit.as_bps() as usize / 8 / 100;
                Some(bytes_per_10ms.clamp(1024, 1024 * 1024 * 64))
            }
            None => None,
        }
    }
}

impl Debug for RateLimiter {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let data = self.data.lock();
        match data.as_ref() {
            Some(data) => write!(f, "RateLimiter: {}", data.rate_limit),
            None => write!(f, "RateLimiter: no limit"),
        }
    }
}

#[derive(Debug, Clone)]
enum RWState {
    RWInner,
    CheckNext(NonZeroU32),
    Wait(NonZeroU32),
}

struct RateLimitedContext {
    limiter: Arc<RateLimiter>,
    jitter: Jitter,
    read_state: RWState,
    read_delay: Option<Delay>,
    write_state: RWState,
    write_delay: Option<Delay>,
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
            limiter_ctx: limiter.map(|limiter| RateLimitedContext {
                limiter,
                jitter: Jitter::new(Duration::new(0, 0), Duration::new(0, 0)),
                read_state: RWState::RWInner,
                read_delay: None,
                write_state: RWState::RWInner,
                write_delay: None,
            }),
        }
    }
}

impl<S: StreamConnection> StreamConnection for RateLimitedStream<S> {
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
                    jitter: Jitter::new(Duration::new(0, 0), Duration::new(0, 0)),
                    read_state: RWState::RWInner,
                    read_delay: None,
                    write_state: RWState::RWInner,
                    write_delay: None,
                });
            }
            None => {
                self.limiter_ctx = None;
            }
        }
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        self.stream.physical_device()
    }
}

impl<S> AsyncRead for RateLimitedStream<S>
where
    S: AsyncRead + Unpin,
{
    #[inline]
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.limiter_ctx.is_none() {
            return Pin::new(&mut self.stream).poll_read(cx, buf);
        }

        let max_once_size = self
            .limiter_ctx
            .as_ref()
            .unwrap()
            .limiter
            .max_receive_once()
            .unwrap_or(buf.capacity());

        loop {
            match self.limiter_ctx.as_ref().unwrap().read_state.clone() {
                RWState::RWInner => {
                    let mut recv_buf = buf.take(std::cmp::min(max_once_size, buf.remaining()));
                    match ready!(Pin::new(&mut self.stream).poll_read(cx, &mut recv_buf)) {
                        Ok(()) => {
                            let readed = recv_buf.filled().len();

                            if readed > 0 {
                                unsafe { buf.assume_init(readed) };
                                buf.advance(readed);

                                // 读取到数据进入CheckNextRead进行检测
                                let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                                limiter_ctx.read_state =
                                    RWState::CheckNext((buf.filled().len() as u32).into_nonzero().unwrap());
                            }

                            return Poll::Ready(Ok(()));
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    };
                }
                RWState::CheckNext(readed) => {
                    let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                    match limiter_ctx.limiter.check_n(readed) {
                        Err(err) => match err {
                            // 检测不通过，需要处理错误情况
                            NegativeMultiDecision::BatchNonConforming(duration) => {
                                // 需要等待一定时间，设置好定时器后尝试等待
                                let duration = limiter_ctx.jitter + duration;
                                limiter_ctx.read_delay = Some(Delay::new(duration));
                                limiter_ctx.read_state = RWState::Wait(readed);
                            }
                            NegativeMultiDecision::InsufficientCapacity => {
                                // 读入的数据超过了最大读取数据，在读取时已经保护过，不应该再进入这个请客
                                unreachable!()
                            }
                        },
                        Ok(..) => {
                            // 检查通过，直接进入下一个循环读取数据
                            limiter_ctx.read_state = RWState::RWInner;
                        }
                    }
                }
                RWState::Wait(readed) => {
                    let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                    ready!(Pin::new(limiter_ctx.read_delay.as_mut().unwrap()).poll(cx));
                    limiter_ctx.read_state = RWState::CheckNext(readed);
                    limiter_ctx.read_delay = None;
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
        if self.limiter_ctx.is_none() {
            return Pin::new(&mut self.stream).poll_write(cx, buf);
        }

        loop {
            match self.limiter_ctx.as_ref().unwrap().write_state.clone() {
                RWState::RWInner => {
                    let max_once_size = self
                        .limiter_ctx
                        .as_ref()
                        .unwrap()
                        .limiter
                        .max_receive_once()
                        .unwrap_or(buf.len());
                    let once_write = std::cmp::min(max_once_size, buf.len());
                    match ready!(Pin::new(&mut self.stream).poll_write(cx, &buf[..once_write])) {
                        Ok(writed) => {
                            if writed > 0 {
                                // 读取到数据进入CheckNextRead进行检测
                                let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                                limiter_ctx.write_state = RWState::CheckNext((writed as u32).into_nonzero().unwrap());
                            }

                            return Poll::Ready(Ok(writed));
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }
                RWState::CheckNext(writed) => {
                    let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                    match limiter_ctx.limiter.check_n(writed) {
                        Err(err) => match err {
                            // 检测不通过，需要处理错误情况
                            NegativeMultiDecision::BatchNonConforming(duration) => {
                                // 需要等待一定时间，设置好定时器后尝试等待
                                let duration = limiter_ctx.jitter + duration;
                                limiter_ctx.write_delay = Some(Delay::new(duration));
                                limiter_ctx.write_state = RWState::Wait(writed);
                            }
                            NegativeMultiDecision::InsufficientCapacity => {
                                // 读入的数据超过了最大读取数据，在读取时已经保护过，不应该再进入这个请客
                                unreachable!()
                            }
                        },
                        Ok(..) => {
                            // 检查通过，直接进入下一个循环读取数据
                            limiter_ctx.write_state = RWState::RWInner;
                        }
                    }
                }
                RWState::Wait(writed) => {
                    let limiter_ctx = self.limiter_ctx.as_mut().unwrap();
                    ready!(Pin::new(limiter_ctx.write_delay.as_mut().unwrap()).poll(cx));
                    limiter_ctx.write_state = RWState::CheckNext(writed);
                    limiter_ctx.write_delay = None;
                }
            }
        }
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

impl<S> AsyncPing for RateLimitedStream<S>
where
    S: AsyncPing + Unpin,
{
    #[inline]
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    #[inline]
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<bool>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_write_ping(cx)
    }
}

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::os::unix::io::{AsRawFd, RawFd};
        impl<S: AsRawFd> AsRawFd for RateLimitedStream<S> {
            fn as_raw_fd(&self) -> RawFd {
                self.stream.as_raw_fd()
            }
        }
    }
}
