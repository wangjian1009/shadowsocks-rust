use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq)]
pub struct KeyBytes(pub [u8; 32]);

impl KeyBytes {
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl KeyBytes {
    pub fn random_from_rng<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut buf = [0u8; 32];
        csprng.fill_bytes(&mut buf);
        Self(buf)
    }
}

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] =
                        u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16).map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = STANDARD.decode(s) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err("Illegal character in key");
                    }
                }
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}

impl AsRef<[u8; 32]> for KeyBytes {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Into<x25519_dalek::StaticSecret> for KeyBytes {
    fn into(self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(self.0)
    }
}

impl Into<x25519_dalek::PublicKey> for KeyBytes {
    fn into(self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.0)
    }
}

impl Into<[u8; 32]> for KeyBytes {
    fn into(self) -> [u8; 32] {
        self.0
    }
}
