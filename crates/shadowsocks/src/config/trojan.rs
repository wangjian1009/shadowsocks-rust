use super::*;

use crate::trojan::protocol::{password_to_hash, HASH_STR_LEN};

#[derive(Clone, Debug, PartialEq)]
pub struct TrojanConfig {
    password: String,
    hash: [u8; HASH_STR_LEN],
}

impl TrojanConfig {
    pub fn new<P>(password: P) -> Self
    where
        P: Into<String>,
    {
        use bytes::Buf;

        let password = password.into();
        let mut hash = [0u8; HASH_STR_LEN];
        password_to_hash(password.as_str()).as_bytes().copy_to_slice(&mut hash);

        TrojanConfig { password, hash }
    }

    /// Set password
    pub fn set_password(&mut self, password: &str) {
        use bytes::Buf;

        self.password = password.to_string();

        password_to_hash(password).as_bytes().copy_to_slice(&mut self.hash);
    }

    /// Get password
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    pub fn hash(&self) -> &[u8; HASH_STR_LEN] {
        &self.hash
    }
}

impl ServerConfig {
    pub(crate) fn from_url_trojan(_parsed: &Url) -> Result<ServerConfig, UrlParseError> {
        Err(UrlParseError::InvalidScheme)
    }
}
