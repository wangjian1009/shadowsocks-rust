use spin::Mutex;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{net::Destination, transport::StreamConnection};

#[cfg(feature = "rate-limit")]
use crate::transport::RateLimiter;

#[derive(Clone)]
pub struct SharedStream {
    inner: Arc<Mutex<Box<dyn StreamConnection + 'static>>>,
}

impl SharedStream {
    #[inline]
    pub fn new<S>(s: S) -> Self
    where
        S: StreamConnection + 'static,
    {
        let inner = Arc::new(Mutex::new(Box::new(s) as Box<dyn StreamConnection + 'static>));
        Self { inner }
    }
}

impl StreamConnection for SharedStream {
    fn local_addr(&self) -> io::Result<Destination> {
        self.inner.lock().local_addr()
    }

    fn check_connected(&self) -> bool {
        self.inner.lock().check_connected()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<Arc<RateLimiter>>) {
        self.inner.lock().set_rate_limit(rate_limit);
    }
}

impl AsyncRead for SharedStream {
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        let inner = inner.as_mut();
        tokio::pin!(inner);
        inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedStream {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.lock();
        let inner = inner.as_mut();
        tokio::pin!(inner);
        inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        let inner = inner.as_mut();
        tokio::pin!(inner);
        inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        let inner = inner.as_mut();
        tokio::pin!(inner);
        inner.poll_shutdown(cx)
    }
}
