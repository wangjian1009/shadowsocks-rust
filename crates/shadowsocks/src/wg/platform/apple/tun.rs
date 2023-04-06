use super::super::tun::*;
use async_trait::async_trait;
use std::error::Error;
use std::fmt;
use std::io::IoSlice;
use tokio::{
    io::{self, split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::Mutex,
};
use tun::AsyncDevice;

pub struct AppleTun {}

pub struct AppleTunReader {
    device: Mutex<ReadHalf<AsyncDevice>>,
}

pub struct AppleTunWriter {
    device: Mutex<WriteHalf<AsyncDevice>>,
}

#[derive(Debug)]
pub enum AppleTunError {
    InvalidData,
    Io(io::Error),
    Closed, // TODO
}

impl fmt::Display for AppleTunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppleTunError::Io(err) => write!(f, "The tunnel write io error {:?}", err),
            AppleTunError::InvalidData => write!(f, "The tunnel write packet invalid"),
            AppleTunError::Closed => write!(f, "The tunnel has been closed"),
        }
    }
}

impl Error for AppleTunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        unimplemented!()
    }

    fn description(&self) -> &str {
        unimplemented!()
    }
}

#[async_trait]
impl Reader for AppleTunReader {
    type Error = AppleTunError;

    async fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        /*
        debug_assert!(
            offset < buf.len(),
            "There is no space for the body of the read"
        );
         */
        let mut rbuf = vec![0u8; 4 + buf.len() - offset];
        let n = self
            .device
            .lock()
            .await
            .read(&mut rbuf)
            .await
            .map_err(|err| AppleTunError::Io(err))?;
        // let n: isize = unsafe { libc::read(self.fd, rbuf[..].as_mut_ptr() as _, buf.len() - offset) };
        if n == 0 {
            Err(AppleTunError::Closed)
        } else if n < 4 {
            tracing::error!("tun read invalid size");
            Err(AppleTunError::InvalidData)
        } else {
            let data_len = (n - 4) as usize;
            // tracing::error!("tun read xxxx: {:?}", &rbuf[..4]);
            buf[offset..(offset + data_len)].copy_from_slice(&rbuf[4..(n as usize)]);
            // conversion is safe
            Ok(data_len)
        }
    }
}

#[async_trait]
impl Writer for AppleTunWriter {
    type Error = AppleTunError;

    async fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        if src.is_empty() {
            tracing::error!("tun write empty packet");
            return Err(Self::Error::InvalidData);
        }

        let mut header = [0u8; 4];

        // Protocol, infer from the original packet
        let protocol = match src[0] >> 4 {
            4 => libc::PF_INET,
            6 => libc::PF_INET6,
            _ => {
                tracing::error!("neither an IPv4 or IPv6 packet");
                return Err(Self::Error::InvalidData);
            }
        };

        let protocol_buf = &mut header[2..];
        let protocol_bytes = (protocol as u16).to_be_bytes();
        protocol_buf.copy_from_slice(&protocol_bytes);

        let bufs = [IoSlice::new(&header), IoSlice::new(src)];
        let n = self
            .device
            .lock()
            .await
            .write_vectored(&bufs)
            .await
            .map_err(|err| AppleTunError::Io(err))?;

        // Packets must be written together with the header
        if n != header.len() + src.len() {
            return Err(AppleTunError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "write_vectored header {} bytes, packet {} bytes, but sent {} bytes",
                    header.len(),
                    src.len(),
                    n
                ),
            )));
        }

        Ok(())
    }
}

impl Tun for AppleTun {
    type Writer = AppleTunWriter;
    type Reader = AppleTunReader;
    type Error = AppleTunError;
}

impl AppleTun {
    #[allow(clippy::type_complexity)]
    pub fn new_from_device(device: AsyncDevice) -> Result<(Vec<AppleTunReader>, AppleTunWriter), AppleTunError> {
        let (r, w) = split(device);
        Ok((
            vec![AppleTunReader { device: Mutex::new(r) }],
            AppleTunWriter { device: Mutex::new(w) },
        ))
    }
}
