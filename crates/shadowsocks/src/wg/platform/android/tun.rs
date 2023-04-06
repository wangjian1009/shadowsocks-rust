use super::super::tun::*;

use async_trait::async_trait;
use std::error::Error;
use std::fmt;
use tun::AsyncDevice;

use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::Mutex,
};

pub struct AndroidTun {}

pub struct AndroidTunReader {
    device: Mutex<ReadHalf<AsyncDevice>>,
}

pub struct AndroidTunWriter {
    device: Mutex<WriteHalf<AsyncDevice>>,
}

pub struct AndroidTunStatus {
    events: Vec<TunEvent>,
}

#[derive(Debug)]
pub enum AndroidTunError {
    InvalidTunDeviceName,
    FailedToOpenCloneDevice,
    SetIFFIoctlFailed,
    GetMTUIoctlFailed,
    NetlinkFailure,
    Closed, // TODO
}

impl fmt::Display for AndroidTunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AndroidTunError::InvalidTunDeviceName => write!(f, "Invalid name (too long)"),
            AndroidTunError::FailedToOpenCloneDevice => {
                write!(f, "Failed to obtain fd for clone device")
            }
            AndroidTunError::SetIFFIoctlFailed => {
                write!(f, "set_iff ioctl failed (insufficient permissions?)")
            }
            AndroidTunError::Closed => write!(f, "The tunnel has been closed"),
            AndroidTunError::GetMTUIoctlFailed => write!(f, "ifmtu ioctl failed"),
            AndroidTunError::NetlinkFailure => write!(f, "Netlink listener error"),
        }
    }
}

impl Error for AndroidTunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        unimplemented!()
    }

    fn description(&self) -> &str {
        unimplemented!()
    }
}

#[async_trait]
impl Reader for AndroidTunReader {
    type Error = AndroidTunError;

    async fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        /*
        debug_assert!(
            offset < buf.len(),
            "There is no space for the body of the read"
        );
         */

        let n = match self.device.lock().await.read(&mut buf[offset..]).await {
            Ok(n) => n,
            Err(err) => {
                tracing::error!(err = ?err, "tun read error");
                return Err(AndroidTunError::NetlinkFailure);
            }
        };

        if n == 0 {
            Err(AndroidTunError::Closed)
        } else {
            // conversion is safe
            Ok(n as usize)
        }
    }
}

#[async_trait]
impl Writer for AndroidTunWriter {
    type Error = AndroidTunError;

    async fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        let n = match self.device.lock().await.write(src).await {
            Ok(n) => n,
            Err(err) => {
                tracing::error!(err = ?err, "tun write error");
                return Err(AndroidTunError::NetlinkFailure);
            }
        };

        if n == 0 {
            Err(AndroidTunError::Closed)
        } else if n != src.len() {
            tracing::error!("write {} bytes, but only write {}", src.len(), n);
            return Err(AndroidTunError::NetlinkFailure);
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Status for AndroidTunStatus {
    type Error = AndroidTunError;

    async fn event(&mut self) -> Result<TunEvent, Self::Error> {
        loop {
            // attempt to return a buffered event
            if let Some(event) = self.events.pop() {
                return Ok(event);
            }

            tokio::task::yield_now().await;
        }
    }
}

impl Tun for AndroidTun {
    type Writer = AndroidTunWriter;
    type Reader = AndroidTunReader;
    type Error = AndroidTunError;
}

impl AndroidTun {
    #[allow(clippy::type_complexity)]
    pub fn new_from_device(device: AsyncDevice) -> Result<(Vec<AndroidTunReader>, AndroidTunWriter), AndroidTunError> {
        let (r, w) = split(device);
        Ok((
            vec![AndroidTunReader { device: Mutex::new(r) }],
            AndroidTunWriter { device: Mutex::new(w) },
        ))
    }
}
