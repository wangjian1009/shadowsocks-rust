use rand::RngCore;
use std::{
    fmt::{self, Write},
    io,
    str::FromStr,
};

use super::new_error;

const BYTE_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

#[derive(PartialEq, Eq, Debug, Hash, Clone)]
pub struct UUID {
    data: [u8; 16],
}

impl UUID {
    // New creates a UUID with random value.
    pub fn new() -> Self {
        let mut data = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut data);
        Self { data }
    }

    // ParseBytes converts a UUID in byte form to object.
    pub fn parse_bytes(b: &[u8]) -> io::Result<Self> {
        if b.len() != 16 {
            return Err(new_error(format!("invalid UUID: {b:?}")));
        }

        let mut data = [0u8; 16];
        data.copy_from_slice(b);
        Ok(Self { data })
    }

    // Bytes returns the bytes representation of this UUID.
    pub fn bytes(&self) -> &'_ [u8; 16] {
        &self.data
    }
}

impl Default for UUID {
    fn default() -> Self {
        Self::new()
    }
}

// ParseString converts a UUID in string form to object.
impl FromStr for UUID {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 32 {
            return Err(new_error(format!("invalid UUID: {s}")));
        }

        let mut uuid = [0u8; 16];

        let mut text = s.as_bytes();
        let mut b: &mut [u8] = &mut uuid;

        for byte_group in BYTE_GROUPS {
            if text[0] == b'-' {
                text = &text[1..];
            }

            hex::decode_to_slice(&text[..byte_group], &mut b[..byte_group / 2]).map_err(new_error)?;

            text = &text[byte_group..];
            b = &mut b[byte_group / 2..];
        }

        Ok(Self { data: uuid })
    }
}

impl fmt::Display for UUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.data[..];
        f.write_str(hex::encode(&bytes[0..BYTE_GROUPS[0] / 2]).as_str())?;
        let mut start = BYTE_GROUPS[0] / 2;
        for v in BYTE_GROUPS.iter().skip(1) {
            let n_bytes = v / 2;
            f.write_char('-')?;
            f.write_str(hex::encode(&bytes[start..start + n_bytes]).as_str())?;
            start += n_bytes;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_bytes() {
        let bytes = [
            0x24, 0x18, 0xd0, 0x87, 0x64, 0x8d, 0x49, 0x90, 0x86, 0xe8, 0x19, 0xdc, 0xa1, 0xd0, 0x06, 0xd3,
        ];

        let uuid = UUID::parse_bytes(&bytes).unwrap();
        assert_eq!(uuid.to_string(), "2418d087-648d-4990-86e8-19dca1d006d3");

        assert_matches!(UUID::parse_bytes(&[1, 3, 2, 4]), Err(..));
    }

    #[test]
    fn test_parse_string() {
        let uuid = "2418d087-648d-4990-86e8-19dca1d006d3".parse::<UUID>().unwrap();
        assert_eq!(
            uuid.bytes(),
            &[0x24, 0x18, 0xd0, 0x87, 0x64, 0x8d, 0x49, 0x90, 0x86, 0xe8, 0x19, 0xdc, 0xa1, 0xd0, 0x06, 0xd3,]
        );

        assert_matches!(UUID::from_str("2418d087"), Err(..));
        assert_matches!(UUID::from_str("2418d087-648k-4990-86e8-19dca1d006d3"), Err(..));
    }

    #[test]
    #[traced_test]
    fn test_new_uuid() {
        let uuid = UUID::new();
        let uuid2 = uuid.to_string().parse::<UUID>().unwrap();

        assert_eq!(uuid.to_string(), uuid2.to_string());
        assert_eq!(uuid, uuid2);
        assert_eq!(uuid.bytes(), uuid2.bytes());
    }

    #[test]
    fn test_random() {
        let uuid1 = UUID::new();
        let uuid2 = UUID::new();

        assert_ne!(uuid1, uuid2);
    }
}
