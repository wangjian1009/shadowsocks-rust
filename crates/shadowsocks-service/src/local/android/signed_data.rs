use cryptographic_message_syntax::SignedData;
use std::io;

pub fn load_signed_data(_data: &[u8]) -> io::Result<SignedData> {
    let signed_data = SignedData::parse_ber(_data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(signed_data)
}

pub fn get_signed_data_sha1_fingerprint(signed_data: &SignedData) -> Option<Vec<u8>> {
    for cert in signed_data.certificates() {
        let digest = super::sha1::sha1(cert.constructed_data());
        let mut buf = Vec::new();
        buf.extend_from_slice(&digest);
        return Some(buf);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_signed_data() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let input_data = base64::decode(
            "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").unwrap();

        let signed_data = load_signed_data(&input_data[..]).expect("parse cert fail");
        assert_eq!(
            get_signed_data_sha1_fingerprint(&signed_data).unwrap()[..],
            vec![
                0x9F, 0xD8, 0x04, 0x63, 0x35, 0xD8, 0x2F, 0x6F, 0x20, 0xF7, 0x57, 0x81, 0x31, 0xD9, 0x2E, 0xC3, 0x56,
                0x78, 0x56, 0xCF
            ],
        );
    }
}
