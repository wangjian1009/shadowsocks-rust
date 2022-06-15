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
    pub(crate) fn from_url_trojan(parsed: &Url) -> Result<ServerConfig, UrlParseError> {
        if parsed.password().is_some() {
            error!("url to config: trojan: password format error");
            return Err(UrlParseError::InvalidAuthInfo);
        }

        let password = parsed.username();

        let trojan_config = TrojanConfig::new(password);

        let mut config = ServerConfig::new(
            Self::from_url_host(parsed, 8388)?,
            ServerProtocol::Trojan(trojan_config),
        );

        if let Some(q) = parsed.query() {
            let query = match serde_urlencoded::from_bytes::<Vec<(String, String)>>(q.as_bytes()) {
                Ok(q) => q,
                Err(err) => {
                    error!("url to config: vless: Failed to parse QueryString, err: {}", err);
                    return Err(UrlParseError::InvalidQueryString);
                }
            };

            #[cfg(feature = "transport")]
            config.set_connector_transport(Self::from_url_transport_connector(&query)?)
        }

        Ok(config)
    }
}
