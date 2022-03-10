use std::io;

use bytes::{Buf, BufMut};

use super::{
    new_error,
    xor::{xorbkd_with_pending, xorfwd_with_pending},
};

pub trait AEAD {
    // NonceSize returns the size of the nonce that must be passed to Seal
    // and Open.
    fn nonce_size(&self) -> usize;

    // Overhead returns the maximum difference between the lengths of a
    // plaintext and its ciphertext.
    fn overhead(&self) -> usize;

    // Seal encrypts and authenticates plaintext, authenticates the
    // additional data and appends the result to dst, returning the updated
    // slice. The nonce must be NonceSize() bytes long and unique for all
    // time, for a given key.
    //
    // To reuse plaintext's storage for the encrypted output, use plaintext[:0]
    // as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
    fn seal(
        &self,
        nonce: &[u8],
        plain_in_cipher_out: &mut [u8],
        plain_len: usize,
        extra: Option<&[u8]>,
    ) -> io::Result<usize>;

    // Open decrypts and authenticates ciphertext, authenticates the
    // additional data and, if successful, appends the resulting plaintext
    // to dst, returning the updated slice. The nonce must be NonceSize()
    // bytes long and both it and the additional data must match the
    // value passed to Seal.
    //
    // To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
    // as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
    //
    // Even if the function fails, the contents of dst, up to its capacity,
    // may be overwritten.
    fn open(&self, nonce: &[u8], cipher_in_plain_out: &mut [u8], extra: Option<&[u8]>) -> io::Result<usize>;
}

pub struct SimpleAuthenticator {}

// NewSimpleAuthenticator creates a new SimpleAuthenticator
impl SimpleAuthenticator {
    pub fn new() -> Self {
        return Self {};
    }
}

impl AEAD for SimpleAuthenticator {
    fn nonce_size(&self) -> usize {
        0
    }

    fn overhead(&self) -> usize {
        6
    }

    // Seal implements cipher.AEAD.Seal().
    fn seal(
        &self,
        _nonce: &[u8],
        plain_in_cipher_out: &mut [u8],
        plain_len: usize,
        _extra: Option<&[u8]>,
    ) -> io::Result<usize> {
        // 4 bytes for hash, and then 2 bytes for length
        let dst_len = 6 + plain_len;
        if plain_in_cipher_out.len() < dst_len {}

        plain_in_cipher_out.copy_within(..plain_len, 6);

        (&mut plain_in_cipher_out[4..]).put_u16(plain_len as u16);

        let hash = fnv_32_hash(&plain_in_cipher_out[4..dst_len]);
        (&mut plain_in_cipher_out[..4]).put_u32(hash);

        xorfwd_with_pending(plain_in_cipher_out, dst_len);
        Ok(dst_len)
    }

    // Open implements cipher.AEAD.Open().
    fn open(&self, _nonce: &[u8], cipher_in_plain_out: &mut [u8], _extra: Option<&[u8]>) -> io::Result<usize> {
        let clen = cipher_in_plain_out.len();
        if clen < 6 {
            return Err(new_error(format!(
                "simple authenticator: invalid auth(cipher len {} too small)",
                clen
            )));
        }

        let plen = clen - 6;

        xorbkd_with_pending(cipher_in_plain_out, clen);

        let hash = (&cipher_in_plain_out[..4]).get_u32();
        if hash != fnv_32_hash(&cipher_in_plain_out[4..clen]) {
            return Err(new_error(format!("simple authenticator: invalid auth(hash)")));
        }

        let length = (&cipher_in_plain_out[4..6]).get_u16() as usize;
        if length + 6 != clen {
            return Err(new_error(format!("simple authenticator: invalid auth(len)")));
        }

        cipher_in_plain_out.copy_within(6..clen, 0);
        Ok(plen)
    }
}

pub fn fnv_32_hash(src: &[u8]) -> u32 {
    const OFFSET_BASIS: u32 = 2166136261; // 32位offset basis
    const PRIME: u32 = 16777619; // 32位prime

    let mut hash = OFFSET_BASIS;
    for b in src {
        hash ^= b.clone() as u32;
        hash = ((hash as u64) * PRIME as u64) as u32;
    }

    hash
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fnv32() {
        let fnv_32_slice = |src| -> [u8; 4] {
            let mut buf = [0; 4];
            (&mut buf[..4]).put_u32(fnv_32_hash(src));
            buf
        };

        assert_eq!([0x81, 0x1c, 0x9d, 0xc5], fnv_32_slice(b""));
        assert_eq!([0xe4, 0x0c, 0x29, 0x2c], fnv_32_slice(b"a"));
        assert_eq!([0x4d, 0x25, 0x05, 0xca], fnv_32_slice(b"ab"));
        assert_eq!([0x1a, 0x47, 0xe9, 0x0b], fnv_32_slice(b"abc"));
    }

    #[test]
    fn simple_authenticator() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .try_init();

        let payload = b"abcdefg";
        let output = seal_then_open(payload, 512).unwrap();
        assert_eq!(payload, &output[..]);
    }

    #[test]
    fn simple_authenticator_2() {
        let payload = b"ab";
        let output = seal_then_open(payload, 512).unwrap();
        assert_eq!(payload, &output[..]);
    }

    fn seal_then_open(plain: &[u8], seal_buf_size: usize) -> io::Result<Vec<u8>> {
        let auth = SimpleAuthenticator::new();

        let mut cache = vec![0; seal_buf_size];
        cache[..plain.len()].copy_from_slice(plain);
        let encrypt_len = auth.seal(&[], &mut cache, plain.len(), None)?;

        let output_len = auth.open(&[], &mut cache[..encrypt_len], None)?;
        Ok(cache[..output_len].to_owned())
    }
}
