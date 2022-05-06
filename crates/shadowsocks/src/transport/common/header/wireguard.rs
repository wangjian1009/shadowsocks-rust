use super::Header;

pub struct Wireguard {}

impl Header for Wireguard {
    fn size(&self) -> usize {
        return 4;
    }

    // Serialize implements PacketHeader.
    fn serialize(&self, b: &mut [u8]) {
        b[0] = 0x04;
        b[1] = 0x00;
        b[2] = 0x00;
        b[3] = 0x00;
    }
}

impl Wireguard {
    pub fn new() -> Self {
        return Self {};
    }
}
