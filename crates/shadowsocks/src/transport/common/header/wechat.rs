use bytes::BufMut;
use std::sync::atomic::{AtomicU32, Ordering};

use super::Header;

pub struct VideoChat {
    sn: AtomicU32,
}

impl Header for VideoChat {
    fn size(&self) -> usize {
        return 13;
    }

    // Serialize implements PacketHeader.
    fn serialize(&self, mut dst: &mut [u8]) {
        let sn = self.sn.fetch_add(1, Ordering::Relaxed);
        dst.put_slice(&[0xa1, 0x08]);
        dst.put_u32(sn);
        dst.put_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
    }
}

impl VideoChat {
    pub fn new() -> Self {
        let sn: u32 = rand::random();
        return Self {
            sn: AtomicU32::new(sn), // uint32(dice.RollUint16()),
        };
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        let video = VideoChat::new();

        let mut payload = vec![0; 15];
        video.serialize(&mut payload);

        // if payload.Len() != video.Size() {
        //     t.Error("expected payload size ", video.Size(), " but got ", payload.Len())
        // }
    }
}
