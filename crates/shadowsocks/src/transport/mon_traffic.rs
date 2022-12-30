use async_trait::async_trait;
use futures::ready;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{net::FlowStat, ServerAddr};

use super::{DeviceOrGuard, PacketMutWrite, PacketRead, PacketWrite, StreamConnection};

#[cfg(feature = "rate-limit")]
use super::RateLimiter;

#[pin_project::pin_project]
pub struct MonTraffic<T> {
    tx: Option<Arc<FlowStat>>,
    rx: Option<Arc<FlowStat>>,
    #[pin]
    s: T,
}

impl<T> MonTraffic<T> {
    #[inline]
    pub fn new_with_tx_rx(s: T, tx: Option<Arc<FlowStat>>, rx: Option<Arc<FlowStat>>) -> Self {
        Self { tx, rx, s }
    }

    #[inline]
    pub fn new(s: T, flow_stat: Option<Arc<FlowStat>>) -> Self {
        let tx = flow_stat.clone();
        let rx = flow_stat;
        Self { tx, rx, s }
    }

    #[inline]
    pub fn set_tx(&mut self, tx: Option<Arc<FlowStat>>) {
        self.tx = tx;
    }

    #[inline]
    pub fn set_rx(&mut self, rx: Option<Arc<FlowStat>>) {
        self.rx = rx;
    }
}

#[async_trait]
impl<T: PacketMutWrite> PacketMutWrite for MonTraffic<T> {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        self.s.write_to_mut(buf, addr).await?;
        if let Some(tx) = self.tx.as_ref() {
            tx.incr_tx(buf.len() as u64);
        }
        Ok(())
    }
}

#[async_trait]
impl<T: PacketWrite> PacketWrite for MonTraffic<T> {
    async fn write_to(&self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        self.s.write_to(buf, addr).await?;
        if let Some(tx) = self.tx.as_ref() {
            tx.incr_tx(buf.len() as u64);
        }
        Ok(())
    }
}

#[async_trait]
impl<T: PacketRead> PacketRead for MonTraffic<T> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let r = self.s.read_from(buf).await?;
        if let Some(rx) = self.rx.as_ref() {
            rx.incr_rx(buf.len() as u64);
        }
        Ok(r)
    }
}

#[async_trait]
impl<T: StreamConnection> StreamConnection for MonTraffic<T> {
    #[inline]
    fn check_connected(&self) -> bool {
        self.s.check_connected()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<Arc<RateLimiter>>) {
        self.s.set_rate_limit(rate_limit)
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        self.s.physical_device()
    }
}

impl<T: AsyncRead> AsyncRead for MonTraffic<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        let r = ready!(this.s.poll_read(cx, buf));
        if r.is_ok() {
            if let Some(rx) = this.rx.as_ref() {
                rx.incr_rx(buf.filled().len() as u64);
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite> AsyncWrite for MonTraffic<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        let r = ready!(this.s.poll_write(cx, buf));
        if let Ok(n) = r {
            if let Some(tx) = this.tx.as_ref() {
                tx.incr_tx(n as u64);
            }
        }
        Poll::Ready(r)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        this.s.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        this.s.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        let r = ready!(this.s.poll_write_vectored(cx, bufs));
        if let Ok(n) = r {
            if let Some(tx) = this.tx.as_ref() {
                tx.incr_tx(n as u64);
            }
        }
        Poll::Ready(r)
    }

    fn is_write_vectored(&self) -> bool {
        self.s.is_write_vectored()
    }
}

#[pin_project::pin_project]
pub struct MonTrafficRead<T> {
    rx: Option<Arc<FlowStat>>,
    #[pin]
    s: T,
}

impl<T> MonTrafficRead<T> {
    #[inline]
    pub fn new(s: T, rx: Option<Arc<FlowStat>>) -> Self {
        Self { rx, s }
    }
}

impl<T: AsyncRead> AsyncRead for MonTrafficRead<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        let r = ready!(this.s.poll_read(cx, buf));
        if r.is_ok() {
            if let Some(rx) = this.rx.as_ref() {
                rx.incr_rx(buf.filled().len() as u64);
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[pin_project::pin_project]
pub struct MonTrafficWrite<T> {
    tx: Option<Arc<FlowStat>>,
    #[pin]
    s: T,
}

impl<T> MonTrafficWrite<T> {
    #[inline]
    pub fn new(s: T, tx: Option<Arc<FlowStat>>) -> Self {
        Self { tx, s }
    }
}

impl<T: AsyncWrite> AsyncWrite for MonTrafficWrite<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        let r = ready!(this.s.poll_write(cx, buf));
        if let Ok(n) = r {
            if let Some(tx) = this.tx.as_ref() {
                tx.incr_tx(n as u64);
            }
        }
        Poll::Ready(r)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        this.s.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        this.s.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        let r = ready!(this.s.poll_write_vectored(cx, bufs));
        if let Ok(n) = r {
            if let Some(tx) = this.tx.as_ref() {
                tx.incr_tx(n as u64);
            }
        }
        Poll::Ready(r)
    }

    fn is_write_vectored(&self) -> bool {
        self.s.is_write_vectored()
    }
}
