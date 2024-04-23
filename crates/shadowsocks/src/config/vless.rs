use super::*;

impl ServerConfig {
    pub(crate) fn from_url_vless(parsed: &Url) -> Result<ServerConfig, UrlParseError> {
        let user_info = parsed.username();

        let vless_config = VlessConfig {
            user_id: user_info.parse().map_err(|e| {
                error!("url to config: vless: user {} invalid, {}", user_info, e);
                UrlParseError::InvalidUserInfo
            })?,
        };

        let mut config = ServerConfig::new(Self::from_url_host(parsed, 8388)?, ServerProtocol::Vless(vless_config));

        if let Some(fragment) = parsed.fragment() {
            config.set_remarks(fragment);
        }

        if let Some(q) = parsed.query() {
            let query = match serde_urlencoded::from_bytes::<Vec<(String, String)>>(q.as_bytes()) {
                Ok(q) => q,
                Err(err) => {
                    error!("url to config: vless: Failed to parse QueryString, err: {}", err);
                    return Err(UrlParseError::InvalidQueryString(format!(
                        "vless parse query error: {:?}",
                        err
                    )));
                }
            };

            #[cfg(feature = "transport")]
            config.set_connector_transport(Self::from_url_transport_connector(
                parsed.host_str().ok_or(UrlParseError::MissingHost)?,
                &query,
            )?)
        }

        Ok(config)
    }

    pub(crate) fn to_url_vless(&self, vless_config: &VlessConfig) -> String {
        let mut url = format!("vless://{}@{}", vless_config.user_id, self.addr());

        let mut params: Vec<(&str, String)> = vec![];

        #[cfg(feature = "transport")]
        if let Some(transport) = self.connector_transport.as_ref() {
            Self::to_url_transport(&mut params, transport);
        }

        if !params.is_empty() {
            url += "/?";
            url += &serde_urlencoded::to_string(&params).unwrap();
        }

        if let Some(desc) = self.remarks() {
            url += "#";
            url += desc;
        }

        url
    }
}
