use super::{Sniffer, SnifferCheckError, SnifferProtocol};
use byteorder::{BigEndian, ByteOrder};

pub struct SnifferTls {}

impl SnifferTls {
    pub fn new() -> SnifferTls {
        SnifferTls {}
    }

    fn is_valid_tls_version(major: u8, _minor: u8) -> bool {
        major == 3
    }

    fn read_client_hello(mut data: &[u8]) -> Result<String, String> {
        if data.len() < 42 {
            return Err("hello message too small".into());
        }

        // session id
        let session_id_len = data[38] as usize;
        if session_id_len > 32 || data.len() < 39 + session_id_len {
            return Err(format!(
                "hello message session-id overflow, session-id-len={}, buf-len={}",
                session_id_len,
                data.len()
            ));
        }

        // cipher_suite
        data = &data[39 + session_id_len..];
        if data.len() < 2 {
            return Err("cipher suite len not enough".into());
        }

        // cipher_suite_len is the number of bytes of cipher suite numbers. Since
        // they are uint16s, the number must be even.
        let cipher_suite_len = BigEndian::read_u16(data) as usize;
        if cipher_suite_len % 2 == 1 {
            return Err("cipher suite len not even".into());
        }

        if data.len() < (2 + cipher_suite_len) {
            return Err("cipher suite overflow".into());
        }

        // compression methods
        data = &data[2 + cipher_suite_len..];
        if data.len() < 1 {
            return Err("compression methods not enough".into());
        }

        let compression_methods_len = data[0] as usize;
        if data.len() < 1 + compression_methods_len {
            return Err("compression methods overflow".into());
        }

        data = &data[1 + compression_methods_len..];
        if data.len() < 2 {
            return Err("extensions length not enough".into());
        }

        let extensions_length = BigEndian::read_u16(data) as usize;
        data = &data[2..];
        if extensions_length != data.len() {
            return Err("extensions length mismatch".into());
        }

        while data.len() != 0 {
            if data.len() < 4 {
                return Err("extension block too small".into());
            }

            let extension = BigEndian::read_u16(data);
            let length = BigEndian::read_u16(&data[2..]) as usize;
            data = &data[4..];
            if data.len() < length {
                return Err("extension block flow".into());
            }

            if extension == 0x00 {
                // extension server name
                let mut d = &data[..length];
                if d.len() < 2 {
                    return Err("extension server name block too small".into());
                }

                let names_len = BigEndian::read_u16(d) as usize;
                d = &d[2..];
                if d.len() != names_len {
                    return Err("extension server name block overflow".into());
                }

                while d.len() > 0 {
                    if d.len() < 3 {
                        return Err("extension server name block part too small".into());
                    }

                    let name_type = d[0];
                    let name_len = BigEndian::read_u16(&d[1..]) as usize;
                    d = &d[3..];

                    if d.len() < name_len {
                        return Err("extension server name block part names too small".into());
                    }

                    if name_type == 0 {
                        let server_name = match String::from_utf8(d[..name_len].to_vec()) {
                            Ok(name) => name,
                            Err(e) => return Err(format!("extension server name format error: {:?}", e)),
                        };

                        // An SNI value may not include a
                        // trailing dot. See
                        // https://tools.ietf.org/html/rfc6066#section-3.
                        if server_name.ends_with(".") {
                            return Err(format!("server name {} format error", server_name));
                        }
                        return Ok(server_name);
                    }

                    d = &d[name_len..];
                }
            }

            data = &data[length..]
        }

        Err("extension server name not found".to_string())
    }
}

impl Sniffer for SnifferTls {
    fn check(&mut self, data: &[u8]) -> Result<SnifferProtocol, SnifferCheckError> {
        if data.len() < 5 {
            return Err(SnifferCheckError::NoClue);
        }

        if data[0] != 0x16 {
            // TLS Handshake
            return Err(SnifferCheckError::Reject);
        }

        if !Self::is_valid_tls_version(data[1], data[2]) {
            return Err(SnifferCheckError::Reject);
        }

        let header_len = BigEndian::read_u16(data[3..5].into());
        if data.len() < (header_len + 5u16) as usize {
            return Err(SnifferCheckError::NoClue);
        }

        match Self::read_client_hello(&data[5..(5 + header_len) as usize]) {
            Ok(domain) => Ok(SnifferProtocol::Tls(domain)),
            Err(err) => Err(SnifferCheckError::Other(err)),
        }
    }
}
