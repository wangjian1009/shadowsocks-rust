//! TCP stream with flow statistic monitored

use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
};

use shadowsocks::{
    net::{Destination, FlowStat},
    timeout::Sleep,
    transport::StreamConnection,
};

/// Monitored `ProxyStream`
#[pin_project]
pub struct MonProxyStream<S> {
    #[pin]
    stream: S,
    flow_stat: Arc<FlowStat>,
    idle_timeout: Option<Arc<Mutex<Sleep>>>,
}

impl<S: StreamConnection> StreamConnection for MonProxyStream<S> {
    #[inline]
    fn local_addr(&self) -> io::Result<Destination> {
        self.stream.local_addr()
    }

    #[inline]
    fn check_connected(&self) -> bool {
        self.stream.check_connected()
    }

    #[cfg(feature = "rate-limit")]
    #[inline]
    fn set_rate_limit(&mut self, limiter: Option<std::sync::Arc<shadowsocks::transport::RateLimiter>>) {
        self.stream.set_rate_limit(limiter);
    }
}

impl<S> MonProxyStream<S> {
    #[inline]
    pub fn from_stream(
        stream: S,
        flow_stat: Arc<FlowStat>,
        idle_timeout: Option<Arc<Mutex<Sleep>>>,
    ) -> MonProxyStream<S> {
        MonProxyStream {
            stream,
            flow_stat,
            idle_timeout,
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

    pub fn get_idle_timeout(&self) -> Option<Arc<Mutex<Sleep>>> {
        match &self.idle_timeout {
            None => None,
            Some(idle_timeout) => Some(idle_timeout.clone()),
        }
    }
}

impl<S> AsyncRead for MonProxyStream<S>
where
    S: AsyncRead + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        match this.stream.poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len();
                this.flow_stat.incr_rx(n as u64);
                if let Some(ref idle_timeout) = this.idle_timeout {
                    let idle_timeout = idle_timeout.clone();
                    tokio::spawn(async move {
                        let mut idle_timeout = idle_timeout.lock().await;
                        idle_timeout.reschedule().await;
                    });
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }
}

impl<S> AsyncWrite for MonProxyStream<S>
where
    S: AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();
        match this.stream.poll_write(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => {
                this.flow_stat.incr_tx(n as u64);
                if let Some(ref idle_timeout) = this.idle_timeout {
                    let idle_timeout = idle_timeout.clone();
                    tokio::spawn(async move {
                        let mut idle_timeout = idle_timeout.lock().await;
                        idle_timeout.reschedule().await;
                    });
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }
}

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(unix)] {
        use std::os::unix::io::{AsRawFd, RawFd};
        impl<S: AsRawFd> AsRawFd for MonProxyStream<S> {
            fn as_raw_fd(&self) -> RawFd {
                self.stream.as_raw_fd()
            }
        }
    }
}
