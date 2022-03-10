//! A TCP stream for communicating with shadowsocks' proxy client

use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};

use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{context::SharedContext, crypto::v1::CipherKind, relay::tcprelay::crypto_io::CryptoStream};

/// A stream for communicating with shadowsocks' proxy client
#[pin_project]
pub struct ProxyServerStream<S> {
    #[pin]
    stream: CryptoStream<S>,
    context: SharedContext,
}

impl<S> ProxyServerStream<S> {
    pub fn from_stream(context: SharedContext, stream: S, method: CipherKind, key: &[u8]) -> ProxyServerStream<S> {
        ProxyServerStream {
            stream: CryptoStream::from_stream(&context, stream, method, key),
            context,
        }
    }

    /// Get reference of the internal stream
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Get mutable reference of the internal stream
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Consumes the object and return the internal stream
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }
}

impl<S> AsyncRead for ProxyServerStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        this.stream.poll_read_decrypted(cx, this.context, buf)
    }
}

impl<S> AsyncWrite for ProxyServerStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        self.project().stream.poll_write_encrypted(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }
}
