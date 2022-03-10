use super::{crypt::AEAD, new_error};
use crypto2::aeadcipher::Aes128Gcm;
use sha2::{Digest, Sha256};
use std::io;

pub struct AEADAESGCMBasedOnSeed {
    block: Aes128Gcm,
}

impl AEADAESGCMBasedOnSeed {
    pub fn new(seed: &str) -> Self {
        let hashed_seed = Sha256::digest(seed.as_bytes());

        Self {
            block: Aes128Gcm::new(&hashed_seed.as_slice()[..16]),
        }
    }
}

impl AEAD for AEADAESGCMBasedOnSeed {
    fn nonce_size(&self) -> usize {
        Aes128Gcm::NONCE_LEN
    }

    fn overhead(&self) -> usize {
        Aes128Gcm::TAG_LEN
    }

    fn seal(
        &self,
        nonce: &[u8],
        plain_in_cipher_out: &mut [u8],
        plen: usize,
        _extra: Option<&[u8]>,
    ) -> io::Result<usize> {
        let tlen = Aes128Gcm::TAG_LEN;
        let clen = tlen + plen;
        if plain_in_cipher_out.len() < clen {
            return Err(new_error(format!(
                "AEADAESGCMBasedOnSeed: seal: dst not enough, dst.len={}, plain.len={}, overhead={}",
                plain_in_cipher_out.len(),
                plen,
                tlen,
            )));
        }

        let aad = [0u8; 0];
        self.block.encrypt_slice(nonce, &aad, &mut plain_in_cipher_out[..clen]);
        Ok(clen)
    }

    fn open<'a>(&self, nonce: &[u8], cipher_in_plain_out: &mut [u8], _extra: Option<&[u8]>) -> io::Result<usize> {
        let tlen = Aes128Gcm::TAG_LEN;
        let clen = cipher_in_plain_out.len();
        if clen < tlen {
            return Err(new_error(format!(
                "AEADAESGCMBasedOnSeed: open: cipher not enough, cipher.len={}, overhead={}",
                clen, tlen,
            )));
        }

        let aad = [0u8; 0];
        self.block.decrypt_slice(nonce, &aad, &mut cipher_in_plain_out[..clen]);

        let plen = clen - tlen;
        Ok(plen)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn authenticator_1() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .try_init();

        let seed = "itest123";
        let payload = b"abcdefg";
        let iv = b"aaaaaaaaaaaa";
        let output = seal_then_open(seed, iv, payload, 512).unwrap();
        assert_eq!(payload, &output[..]);
    }

    fn seal_then_open(seed: &str, iv: &[u8], plain: &[u8], seal_buf_size: usize) -> io::Result<Vec<u8>> {
        let auth = AEADAESGCMBasedOnSeed::new(seed);

        let mut cache = vec![0; seal_buf_size];
        cache[..plain.len()].copy_from_slice(plain);
        let encrypt_len = auth.seal(iv, &mut cache, plain.len(), None)?;

        let clen = auth.open(iv, &mut cache[..encrypt_len], None)?;
        Ok(cache[..clen].to_owned())
    }
}
