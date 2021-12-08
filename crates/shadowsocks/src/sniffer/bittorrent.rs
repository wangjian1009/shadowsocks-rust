use super::{Sniffer, SnifferCheckError, SnifferProtocol};

const BITTORRENT_PROTOCOL_INDICATE: &[u8] = b"\x13BitTorrent protocol";

pub struct SnifferBittorrent {}

impl SnifferBittorrent {
    pub fn new() -> SnifferBittorrent {
        SnifferBittorrent {}
    }
}

impl Sniffer for SnifferBittorrent {
    const PROTOCOL: SnifferProtocol = SnifferProtocol::Bittorrent;

    fn check(&mut self, data: &[u8]) -> Result<(), SnifferCheckError> {
        if data.len() < BITTORRENT_PROTOCOL_INDICATE.len() {
            if data == &BITTORRENT_PROTOCOL_INDICATE[..data.len()] {
                Err(SnifferCheckError::NoClue)
            } else {
                Err(SnifferCheckError::Reject)
            }
        } else {
            if &data[..BITTORRENT_PROTOCOL_INDICATE.len()] == BITTORRENT_PROTOCOL_INDICATE {
                Ok(())
            } else {
                Err(SnifferCheckError::Reject)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{super::*, *};

    #[test]
    fn bittorrent_basic() {
        let mut sniffer = SnifferBittorrent::new();
        assert_eq!(Err(SnifferCheckError::NoClue), sniffer.check(&[]));

        assert_eq!(Err(SnifferCheckError::Reject), sniffer.check(&[18]));
        assert_eq!(Err(SnifferCheckError::NoClue), sniffer.check(&[19]));

        assert_eq!(Err(SnifferCheckError::Reject), sniffer.check(b"\x13Bid"));
        assert_eq!(Err(SnifferCheckError::NoClue), sniffer.check(b"\x13BitTorrent protoco"));

        assert_eq!(Ok(()), sniffer.check(b"\x13BitTorrent protocol"));
        assert_eq!(Ok(()), sniffer.check(b"\x13BitTorrent protocol1"));
    }
}
