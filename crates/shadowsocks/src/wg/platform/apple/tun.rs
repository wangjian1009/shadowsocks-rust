use super::super::tun::*;

use std::error::Error;
use std::fmt;
use std::os::unix::io::RawFd;

pub struct AppleTun {}

pub struct AppleTunReader {
    fd: RawFd,
}

pub struct AppleTunWriter {
    fd: RawFd,
}

#[derive(Debug)]
pub enum AppleTunError {
    Closed, // TODO
}

impl fmt::Display for AppleTunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

impl Reader for AppleTunReader {
    type Error = AppleTunError;

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        /*
        debug_assert!(
            offset < buf.len(),
            "There is no space for the body of the read"
        );
        */
        let n: isize = unsafe { libc::read(self.fd, buf[offset..].as_mut_ptr() as _, buf.len() - offset) };
        if n < 0 {
            Err(AppleTunError::Closed)
        } else {
            // conversion is safe
            Ok(n as usize)
        }
    }
}

impl Writer for AppleTunWriter {
    type Error = AppleTunError;

    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        match unsafe { libc::write(self.fd, src.as_ptr() as _, src.len() as _) } {
            -1 => Err(AppleTunError::Closed),
            _ => Ok(()),
        }
    }
}

impl Tun for AppleTun {
    type Writer = AppleTunWriter;
    type Reader = AppleTunReader;
    type Error = AppleTunError;
}

impl AppleTun {
    #[allow(clippy::type_complexity)]
    pub fn new_from_fd(fd: RawFd) -> Result<(Vec<AppleTunReader>, AppleTunWriter), AppleTunError> {
        // create PlatformTunMTU instance
        Ok((
            vec![AppleTunReader { fd }], // TODO: use multi-queue for Apple
            AppleTunWriter { fd },
        ))
    }
}
