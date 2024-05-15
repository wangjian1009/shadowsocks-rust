use rand::RngCore;
use std::{
    io::{self, ErrorKind, Write},
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::mpsc;

use crate::net::UdpSocket;

use super::super::{HeaderPolicy, Security};
use super::kcp::KcpResult;

#[inline]
pub fn calc_overhead(header: &Option<Arc<HeaderPolicy>>, security: &Option<Arc<Security>>) -> usize {
    header.as_ref().map_or(0, |h| h.size()) + security.as_ref().map_or(0, |h| h.overhead() + h.nonce_size())
}

/// Writer for sending packets to the underlying UdpSocket
pub struct UdpOutput {
    socket: Arc<UdpSocket>,
    target_addr: SocketAddr,
    delay_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl UdpOutput {
    /// Create a new Writer for writing packets to UdpSocket
    pub fn new(socket: Arc<UdpSocket>, target_addr: SocketAddr) -> UdpOutput {
        let (delay_tx, mut delay_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        {
            let socket = socket.clone();
            tokio::spawn(async move {
                while let Some(buf) = delay_rx.recv().await {
                    if let Err(err) = socket.send_to(&buf, target_addr).await {
                        tracing::error!("[SEND] UDP delayed send failed, error: {}", err);
                    }
                }
            }.in_current_span());
        }

        UdpOutput {
            socket,
            target_addr,
            delay_tx,
        }
    }
}

impl Write for UdpOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.socket.try_send_to(buf, self.target_addr) {
            Ok(n) => Ok(n),
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                // send return EAGAIN
                // ignored as packet was lost in transmission
                tracing::trace!("[SEND] UDP send EAGAIN, packet.size: {} bytes, delayed send", buf.len());

                self.delay_tx.send(buf.to_owned()).expect("channel closed unexpectly");

                Ok(buf.len())
            }
            Err(err) => Err(err),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct DecorateOutput<W: Write> {
    writer: W,
    header: Option<Arc<HeaderPolicy>>,
    security: Option<Arc<Security>>,
    presend_buf: Option<Vec<u8>>,
}

impl<W: Write> DecorateOutput<W> {
    /// Create a new Writer for writing packets to UdpSocket
    pub fn new(
        writer: W,
        header: Option<Arc<HeaderPolicy>>,
        security: Option<Arc<Security>>,
        presend_buf: Option<Vec<u8>>,
    ) -> Self {
        Self {
            writer,
            header,
            security,
            presend_buf,
        }
    }
}

impl<W: Write> Write for DecorateOutput<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.header.is_none() && self.security.is_none() {
            return self.writer.write(buf);
        }

        let overhead = calc_overhead(&self.header, &self.security);

        let total_len = overhead + buf.len();
        let presend_buf = self.presend_buf.as_mut().unwrap();

        if total_len > presend_buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "skcp: output len overflow, len={}, overhead={}, limit={}",
                    buf.len(),
                    overhead,
                    presend_buf.len()
                ),
            ));
        }

        let mut header_size = 0;
        if let Some(header) = self.header.as_ref() {
            header_size = header.size();
            header.serialize(&mut presend_buf[..header_size]);
        }

        if let Some(security) = self.security.as_ref() {
            let nonce_size = security.nonce_size();
            let (nonce, data) = presend_buf[header_size..].split_at_mut(nonce_size);

            if nonce_size > 0 {
                let mut rng = rand::thread_rng();
                loop {
                    rng.fill_bytes(nonce);
                    let is_zeros = nonce.iter().all(|&x| x == 0);
                    if !is_zeros {
                        break;
                    }
                }
            }

            let slen = security.seal(nonce, buf, data, None)?;
            assert_eq!(header_size + nonce_size + slen, total_len);
        } else {
            presend_buf[header_size..total_len].copy_from_slice(buf);
        }

        let send_buf = &presend_buf[..total_len];
        // tracing::error!("xxxxx: encode: {:?}", send_buf);
        self.writer.write(send_buf).map(|_n| buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[derive(Clone)]
pub struct InputDecorate {
    mtu: usize,
    header: Option<Arc<HeaderPolicy>>,
    security: Option<Arc<Security>>,
    decode_buf: Option<Vec<u8>>,
}

impl InputDecorate {
    #[inline]
    pub fn new(mtu: usize, header: Option<Arc<HeaderPolicy>>, security: Option<Arc<Security>>) -> Self {
        Self {
            mtu,
            header,
            security,
            decode_buf: None,
        }
    }

    pub fn decode<'a>(&'a mut self, mut buf: &'a mut [u8]) -> KcpResult<&'a mut [u8]> {
        // tracing::error!("xxxxx: decode: {:?}", byte_string::ByteStr::new(buf));
        if let Some(header) = self.header.as_ref() {
            buf = &mut buf[header.size()..];
        }

        if let Some(security) = self.security.as_ref() {
            #[allow(clippy::uninit_vec)]
            let decode_buf = if self.decode_buf.is_none() {
                let mut new_buf = Vec::<u8>::with_capacity(self.mtu);
                unsafe { new_buf.set_len(self.mtu) };
                self.decode_buf.insert(new_buf)
            } else {
                self.decode_buf.as_mut().unwrap()
            };

            let (nonce, data) = buf.split_at(security.nonce_size());

            let sz = security.open(nonce, data, decode_buf, None)?;
            Ok(&mut decode_buf[..sz])
        } else {
            Ok(buf)
        }
    }
}
