use super::{Sniffer, SnifferCheckError, SnifferProtocol};
use byteorder::{BigEndian, ByteOrder};
// use std::time::Instant;

pub struct SnifferUtp {}

impl SnifferUtp {
    pub fn new() -> SnifferUtp {
        SnifferUtp {}
    }
}

impl Default for SnifferUtp {
    fn default() -> Self {
        Self::new()
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
            return Err(SnifferCheckError::NoClue);
        }

        // type_and_version
        let type_and_version = data[0];
        data = &data[1..];
        let pdu_type = (type_and_version >> 4) & 0x0F;
        let pdu_version = type_and_version & 0x0F;
        if pdu_type > 4 || pdu_version != 1 {
            return Err(SnifferCheckError::Reject);
        }

        // extension
        loop {
            if data.is_empty() {
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

            if data.is_empty() {
                return Err(SnifferCheckError::NoClue);
            }
            let length = data[0] as usize;
            data = &data[1..];

            if data.len() < length {
                return Err(SnifferCheckError::NoClue);
            }
            data = &data[length..];
        }

        // connection_id
        if data.len() < 2 {
            return Err(SnifferCheckError::NoClue);
        }
        data = &data[2..];

        if data.len() < 4 {
            return Err(SnifferCheckError::NoClue);
        }
        let _timestamp = BigEndian::read_u32(data) as u64;
        data = &data[4..];

        // let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;

        // tracing::error!("xxxxx: now={}, timestamp={}", now, _timestamp);

        // let duration = if now > _timestamp {
        //     now - _timestamp
        // } else {
        //     _timestamp - now
        // };

        // if duration > (24 * 60 * 60 * 1000) as u64 {
        //     // 24小时以上，则认为不是此协议
        //     return Err(SnifferCheckError::Reject);
        // }

        // go 的例子代码，来自于v2ray，只是逻辑不明白，32位时间戳如何处理
        // if math.Abs(float64(time.Now().UnixMicro()-int64(timestamp))) > float64(24*time.Hour) {
        //     return nil, errNotBittorrent
        // }

        if data.len() < 12 {
            return Err(SnifferCheckError::NoClue);
        }

        Ok(SnifferProtocol::Utp)
    }
}
