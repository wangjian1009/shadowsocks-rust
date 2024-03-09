use super::*;

pub use crate::trojan::Config as TrojanConfig;

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
                    return Err(UrlParseError::InvalidQueryString(format!("trojan parse query error: {:?}", err)));
                }
            };

            #[cfg(feature = "transport")]
            config.set_connector_transport(Self::from_url_transport_connector(&query)?)
        }

        Ok(config)
    }
}
