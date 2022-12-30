use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use bytes::BufMut;

use super::Header;

pub struct DTLS {
    epoch: u16,
    length: AtomicU16,
    sequence: AtomicU32,
}

impl Header for DTLS {
    fn size(&self) -> usize {
        1 + 2 + 2 + 6 + 2
    }

    // Serialize implements PacketHeader.
    fn serialize(&self, mut b: &mut [u8]) {
        b.put_u8(23); // application data
        b.put_u8(254);
        b.put_u8(253);
        b.put_u16(self.epoch);
        b.put_u8(0);
        b.put_u8(0);
        b.put_u32(self.sequence.fetch_add(1, Ordering::SeqCst));

        let mut length = self.length.load(Ordering::Acquire);
        b.put_u16(length);
        length += 17;
        if length > 100 {
            length -= 50;
        }
        self.length.store(length, Ordering::Release);
    }
}

impl DTLS {
    pub fn new() -> Self {
        let epoch: u16 = rand::random();
        Self {
            epoch,
            sequence: AtomicU32::new(0),
            length: AtomicU16::new(17),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        let video = DTLS::new();

        let mut payload = vec![0; 15];
        video.serialize(&mut payload);
    }
}
