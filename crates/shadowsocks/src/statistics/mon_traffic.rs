use async_trait::async_trait;
use futures::ready;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    transport::{DeviceOrGuard, PacketMutWrite, PacketRead, PacketWrite, StreamConnection},
    ServerAddr,
};

use super::{BuContext, TrafficNet, TrafficWay};

#[cfg(feature = "rate-limit")]
use crate::transport::RateLimiter;

#[pin_project::pin_project]
pub struct MonTraffic<T> {
    context: BuContext,
    key: &'static str,
    #[pin]
    s: T,
}

impl<T> MonTraffic<T> {
    #[inline]
    pub fn new(s: T, context: BuContext, key: &'static str) -> Self {
        Self { context, key, s }
    }
}

#[async_trait]
impl<T: PacketMutWrite> PacketMutWrite for MonTraffic<T> {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        self.s.write_to_mut(buf, addr).await?;
        self.context
            .count_traffic(self.key, buf.len() as u64, TrafficNet::Tcp, TrafficWay::Send);
        Ok(())
    }
}

#[async_trait]
impl<T: PacketWrite> PacketWrite for MonTraffic<T> {
    async fn write_to(&self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        self.s.write_to(buf, addr).await?;
        self.context
            .count_traffic(self.key, buf.len() as u64, TrafficNet::Tcp, TrafficWay::Send);
        Ok(())
    }
}

#[async_trait]
impl<T: PacketRead> PacketRead for MonTraffic<T> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let r = self.s.read_from(buf).await?;
        self.context
            .count_traffic(self.key, buf.len() as u64, TrafficNet::Tcp, TrafficWay::Recv);
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
            this.context
                .count_traffic(this.key, buf.filled().len() as u64, TrafficNet::Tcp, TrafficWay::Recv);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite> AsyncWrite for MonTraffic<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        let r = ready!(this.s.poll_write(cx, buf));
        if let Ok(n) = r {
            this.context
                .count_traffic(this.key, n as u64, TrafficNet::Tcp, TrafficWay::Send);
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
            this.context
                .count_traffic(this.key, n as u64, TrafficNet::Tcp, TrafficWay::Send);
        }
        Poll::Ready(r)
    }

    fn is_write_vectored(&self) -> bool {
        self.s.is_write_vectored()
    }
}

#[pin_project::pin_project]
pub struct MonTrafficRead<T> {
    context: BuContext,
    key: &'static str,
    #[pin]
    s: T,
}

impl<T> MonTrafficRead<T> {
    #[inline]
    pub fn new(s: T, context: BuContext, key: &'static str) -> Self {
        Self { context, key, s }
    }
}

impl<T: AsyncRead> AsyncRead for MonTrafficRead<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        let r = ready!(this.s.poll_read(cx, buf));
        if r.is_ok() {
            this.context
                .count_traffic(this.key, buf.filled().len() as u64, TrafficNet::Tcp, TrafficWay::Recv);
        }
        Poll::Ready(Ok(()))
    }
}

#[pin_project::pin_project]
pub struct MonTrafficWrite<T> {
    context: BuContext,
    key: &'static str,
    #[pin]
    s: T,
}

impl<T> MonTrafficWrite<T> {
    #[inline]
    pub fn new(s: T, context: BuContext, key: &'static str) -> Self {
        Self { context, key, s }
    }
}

impl<T: AsyncWrite> AsyncWrite for MonTrafficWrite<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        let r = ready!(this.s.poll_write(cx, buf));
        if let Ok(n) = r {
            this.context
                .count_traffic(this.key, n as u64, TrafficNet::Tcp, TrafficWay::Send);
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
            this.context
                .count_traffic(this.key, n as u64, TrafficNet::Tcp, TrafficWay::Send);
        }
        Poll::Ready(r)
    }

    fn is_write_vectored(&self) -> bool {
        self.s.is_write_vectored()
    }
}
