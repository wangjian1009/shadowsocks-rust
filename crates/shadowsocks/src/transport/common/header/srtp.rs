use bytes::BufMut;
use std::sync::atomic::{AtomicU16, Ordering};

use super::Header;

pub struct SRTP {
    header: u16,
    number: AtomicU16,
}

impl Header for SRTP {
    fn size(&self) -> usize {
        return 4;
    }

    // Serialize implements PacketHeader.
    fn serialize(&self, mut dst: &mut [u8]) {
        let number = self.number.fetch_add(1, Ordering::Relaxed);
        dst.put_u16(self.header);
        dst.put_u16(number);
    }
}

impl SRTP {
    pub fn new() -> Self {
        let number: u16 = rand::random();
        return Self {
            header: 0xB5E8,
            number: AtomicU16::new(number),
        };
    }
}
