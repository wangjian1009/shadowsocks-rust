use super::crypt::AEAD;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use sha2::{Digest, Sha256};
use std::io;

pub struct AEADAESGCMBasedOnSeed {
    block: Aes128Gcm,
}

impl AEADAESGCMBasedOnSeed {
    pub fn new(seed: &str) -> Self {
        let hashed_seed = Sha256::digest(seed.as_bytes());
        let key = Key::from_slice(&hashed_seed.as_slice()[..16]);
        Self {
            block: Aes128Gcm::new(key),
        }
    }
}

impl AEAD for AEADAESGCMBasedOnSeed {
    fn nonce_size(&self) -> usize {
        12 // Aes128Gcm::NONCE_LEN
    }

    fn overhead(&self) -> usize {
        16 // Aes128Gcm::TAG_LEN
    }

    fn seal(&self, nonce: &[u8], plain_in: &[u8], cipher_out: &mut [u8], _extra: Option<&[u8]>) -> io::Result<usize> {
        // let tlen = Aes128Gcm::TAG_LEN;
        // let clen = tlen + plen;
        // if plain_in_cipher_out.len() < clen {
        //     return Err(new_error(format!(
        //         "AEADAESGCMBasedOnSeed: seal: dst not enough, dst.len={}, plain.len={}, overhead={}",
        //         plain_in_cipher_out.len(),
        //         plen,
        //         tlen,
        //     )));
        // }

        let nonce = Nonce::from_slice(nonce);
        let output = self
            .block
            .encrypt(nonce, plain_in)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if output.len() > cipher_out.len() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "AEADAESGCMBasedOnSeed: seal: dst not enough, plain.len={}, require={}, but={}",
                    plain_in.len(),
                    output.len(),
                    cipher_out.len(),
                ),
            ));
        }

        cipher_out[..output.len()].copy_from_slice(&output[..]);
        Ok(output.len())
    }

    fn open<'a>(
        &self,
        nonce: &[u8],
        cipher_in: &[u8],
        plain_out: &mut [u8],
        _extra: Option<&[u8]>,
    ) -> io::Result<usize> {
        // let tlen = Aes128Gcm::TAG_LEN;
        // let clen = cipher_in_plain_out.len();
        // if clen < tlen {
        //     return Err(new_error(format!(
        //         "AEADAESGCMBasedOnSeed: open: cipher not enough, cipher.len={}, overhead={}",
        //         clen, tlen,
        //     )));
        // }

        // let aad = [0u8; 0];
        // let mut buf = &mut cipher_in_plain_out[..clen];
        // self.block.decrypt_slice(nonce, &aad, &mut cipher_in_plain_out[..clen]);

        // let plen = clen - tlen;
        // Ok(plen)

        let nonce = Nonce::from_slice(nonce);
        let output = self
            .block
            .decrypt(nonce, &cipher_in[..])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if output.len() > plain_out.len() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "AEADAESGCMBasedOnSeed: open: dst not enough, require={}, but={}",
                    output.len(),
                    plain_out.len(),
                ),
            ));
        }

        plain_out[..output.len()].copy_from_slice(&output[..]);
        Ok(output.len())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[traced_test]
    fn authenticator_1() {
        let seed = "itest123";
        let payload = b"abcdefg";
        let iv = b"aaaaaaaaaaaa";
        let output = seal_then_open(seed, iv, payload, 512).unwrap();
        assert_eq!(payload, &output[..]);
    }

    fn seal_then_open(seed: &str, iv: &[u8], plain: &[u8], seal_buf_size: usize) -> io::Result<Vec<u8>> {
        let auth = AEADAESGCMBasedOnSeed::new(seed);

        let mut cache = vec![0; seal_buf_size];
        let encrypt_len = auth.seal(iv, plain, &mut cache, None)?;

        assert_eq!(plain.len() + auth.overhead(), encrypt_len);

        let mut rebuild = vec![0u8; plain.len()];
        let _clen = auth.open(iv, &cache[..encrypt_len], &mut rebuild, None)?;
        Ok(rebuild)
    }
}
