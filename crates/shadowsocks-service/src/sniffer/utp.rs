use super::{Sniffer, SnifferCheckError, SnifferProtocol};
use byteorder::{BigEndian, ByteOrder};
// use std::time::Instant;

pub struct SnifferUtp {}

impl SnifferUtp {
    pub fn new() -> SnifferUtp {
        SnifferUtp {}
    }
}

// 0       4       8               16              24              32
// +-------+-------+---------------+---------------+---------------+
// | type  | ver   | extension     | connection_id                 |
// +-------+-------+---------------+---------------+---------------+
// | timestamp_microseconds                                        |
// +---------------+---------------+---------------+---------------+
// | timestamp_difference_microseconds                             |
// +---------------+---------------+---------------+---------------+
// | wnd_size                                                      |
// +---------------+---------------+---------------+---------------+
// | seq_nr                        | ack_nr                        |
// +---------------+---------------+---------------+---------------+

impl Sniffer for SnifferUtp {
    fn check(&mut self, mut data: &[u8]) -> Result<SnifferProtocol, SnifferCheckError> {
        if data.len() < 20 {
            log::error!("utp check: total len too small: len={}", data.len());
            return Err(SnifferCheckError::NoClue);
        }

        // type_and_version
        let type_and_version = data[0];
        data = &data[1..];
        let pdu_type = (type_and_version >> 4) & 0x0F;
        let pdu_version = type_and_version & 0x0F;
        if pdu_type > 4 || pdu_version != 1 {
            log::error!("utp check: 22: type={:X}, ver={:X}", pdu_type, pdu_version);
            return Err(SnifferCheckError::Reject);
        }

        // extension
        loop {
            if data.len() < 1 {
                log::error!("utp check: 333");
                return Err(SnifferCheckError::NoClue);
            }
            let extension = data[0];
            data = &data[1..];

            if extension == 0 {
                break;
            }

            if extension != 1 {
                return Err(SnifferCheckError::Reject);
            }

            if data.len() < 1 {
                return Err(SnifferCheckError::NoClue);
            }
            let length = data[0] as usize;
            data = &data[1..];

            if length < data.len() {
                return Err(SnifferCheckError::NoClue);
            }
            data = &data[length..];
        }

        // connection_id
        if data.len() < 2 {
            log::error!("utp check: 444");
            return Err(SnifferCheckError::NoClue);
        }
        data = &data[2..];

        if data.len() < 4 {
            return Err(SnifferCheckError::NoClue);
        }
        let timestamp = BigEndian::read_u32(data);
        data = &data[4..];

        // if math.Abs(float64(time.Now().UnixMicro()-int64(timestamp))) > float64(24*time.Hour) {
        //     return nil, errNotBittorrent
        // }

        if data.len() < 12 {
            return Err(SnifferCheckError::NoClue);
        }

        Ok(SnifferProtocol::Utp)
    }
}
