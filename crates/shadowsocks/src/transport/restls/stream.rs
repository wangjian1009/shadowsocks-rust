use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

use crate::transport::DeviceOrGuard;

use super::super::StreamConnection;

use super::utils::TLSStream;

#[cfg(feature = "rate-limit")]
use super::super::rate_limit::RateLimiter;

pub struct RestlsStream<S: StreamConnection> {
    tls_stream: TLSStream<S>,
    discard: usize,
    out_buf: [u8; 0x2000],
}

impl<S: StreamConnection> RestlsStream<S> {
    pub fn new(tls_stream: TLSStream<S>, discard: usize) -> Self {
        let mut out_buf = [0; 0x2000];
        out_buf[..3].copy_from_slice(&[0x17, 0x03, 0x03]);

        Self {
            tls_stream,
            discard,
            out_buf,
        }
    }

    fn get_mut(&mut self) -> &mut S {
        self.tls_stream.get_mut()
    }

    fn get_ref(&self) -> &S {
        self.tls_stream.get_ref()
    }
}

impl<S: StreamConnection> AsyncRead for RestlsStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        unimplemented!()
    }
}

impl<S: StreamConnection> AsyncWrite for RestlsStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        unimplemented!()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unimplemented!()
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unimplemented!()
    }
}

impl<S: StreamConnection> StreamConnection for RestlsStream<S> {
    fn check_connected(&self) -> bool {
        self.get_ref().check_connected()
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<Arc<RateLimiter>>) {
        self.get_mut().set_rate_limit(rate_limit)
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        self.get_ref().physical_device()
    }
}

// pub async fn copy_bidirectional<SI, SO>(
//     mut inbound: TLSStream<SI>,
//     mut outbound: SO,
//     mut content_offset: usize,
// ) -> Result<()>
// where
//     SI: StreamConnection,
//     SO: StreamConnection,
// {
//     let mut out_buf = [0; 0x2000];
//     out_buf[..3].copy_from_slice(&[0x17, 0x03, 0x03]);
//     while inbound.codec().has_next() {
//         outbound
//             .write_all(&inbound.codec_mut().next_record()[content_offset..])
//             .await?;
//         content_offset = 5;
//     }

//     inbound.codec_mut().reset();

//     loop {
//         select! {
//             res = inbound.next() => {
//                 match res {
//                     Some(Ok(_)) => (),
//                     None => {
//                         return Ok(());
//                     }
//                     Some(Err(e)) => {
//                         return Err(e);
//                     }
//                 }
//                 while inbound.codec().has_next() {
//                     outbound
//                         .write_all(&inbound.codec_mut().next_record()[5..])
//                         .await?;
//                 }
//                 inbound.codec_mut().reset();
//             }
//             n = outbound.read(&mut out_buf[5..]) => {
//                 let n = n?;
//                 if n == 0 {
//                     return Ok(());
//                 }
//                 out_buf[3..5].copy_from_slice(&(n as u16).to_be_bytes());
//                 inbound.get_mut().write_all(&out_buf[..n+5]).await?;
//             }
//         }
//     }
// }
