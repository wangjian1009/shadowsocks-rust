use bytes::BufMut;

use super::Header;

#[allow(clippy::upper_case_acronyms)]
pub struct UTP {
    header: u8,
    extension: u8,
    connection_id: u16,
}

impl Header for UTP {
    fn size(&self) -> usize {
        4
    }

    // Serialize implements PacketHeader.
    fn serialize(&self, mut dst: &mut [u8]) {
        dst.put_u16(self.connection_id);
        dst.put_u8(self.header);
        dst.put_u8(self.extension);
    }
}

impl UTP {
    pub fn new() -> Self {
        let connection_id: u16 = rand::random();
        Self {
            header: 1,
            extension: 0,
            connection_id,
        }
    }
}
