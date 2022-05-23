use spin::Mutex;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::transport::{DeviceGuard, DeviceOrGuard, StreamConnection};

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

struct DeviceLockGuard<'a> {
    lock_guard: spin::MutexGuard<'a, Box<dyn StreamConnection + 'static>>,
}

impl<'a> DeviceGuard for DeviceLockGuard<'a> {
    fn device(&self) -> DeviceOrGuard<'_> {
        self.lock_guard.physical_device()
    }
}

impl StreamConnection for SharedStream {
    fn check_connected(&self) -> bool {
        self.inner.lock().check_connected()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<Arc<RateLimiter>>) {
        self.inner.lock().set_rate_limit(rate_limit);
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        DeviceOrGuard::Guard(Box::new(DeviceLockGuard {
            lock_guard: self.inner.lock(),
        }))
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
