use super::super::tun::*;

use std::error::Error;
use std::fmt;
use std::os::unix::io::RawFd;

pub struct AndroidTun {}

pub struct AndroidTunReader {
    fd: RawFd,
}

pub struct AndroidTunWriter {
    fd: RawFd,
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

impl Reader for AndroidTunReader {
    type Error = AndroidTunError;

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        /*
        debug_assert!(
            offset < buf.len(),
            "There is no space for the body of the read"
        );
        */
        let n: isize = unsafe { libc::read(self.fd, buf[offset..].as_mut_ptr() as _, buf.len() - offset) };
        if n < 0 {
            Err(AndroidTunError::Closed)
        } else {
            // conversion is safe
            Ok(n as usize)
        }
    }
}

impl Writer for AndroidTunWriter {
    type Error = AndroidTunError;

    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        match unsafe { libc::write(self.fd, src.as_ptr() as _, src.len() as _) } {
            -1 => Err(AndroidTunError::Closed),
            _ => Ok(()),
        }
    }
}

impl Status for AndroidTunStatus {
    type Error = AndroidTunError;

    fn event(&mut self) -> Result<TunEvent, Self::Error> {
        loop {
            // attempt to return a buffered event
            if let Some(event) = self.events.pop() {
                return Ok(event);
            }

            std::thread::park();
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
    pub fn new_from_fd(fd: RawFd) -> Result<(Vec<AndroidTunReader>, AndroidTunWriter), AndroidTunError> {
        // create PlatformTunMTU instance
        Ok((
            vec![AndroidTunReader { fd }], // TODO: use multi-queue for Android
            AndroidTunWriter { fd },
        ))
    }
}
