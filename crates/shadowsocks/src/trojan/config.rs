use super::protocol::{password_to_hash, HASH_STR_LEN};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    password: String,
    hash: Arc<[u8; HASH_STR_LEN]>,
}

impl Config {
    pub fn new<P>(password: P) -> Self
    where
        P: Into<String>,
    {
        use bytes::Buf;

        let password = password.into();
        let mut hash = [0u8; HASH_STR_LEN];
        password_to_hash(password.as_str()).as_bytes().copy_to_slice(&mut hash);

        Config {
            password,
            hash: Arc::new(hash),
        }
    }

    /// Set password
    pub fn set_password(&mut self, password: &str) {
        use bytes::Buf;

        self.password = password.to_string();
        let mut hash = [0u8; HASH_STR_LEN];
        password_to_hash(password).as_bytes().copy_to_slice(&mut hash);

        self.hash = Arc::new(hash);
    }

    /// Get password
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    pub fn hash(&self) -> Arc<[u8; HASH_STR_LEN]> {
        self.hash.clone()
    }
}
