use super::*;

impl ServerConfig {
    pub(crate) fn from_url_vless(parsed: &Url) -> Result<ServerConfig, UrlParseError> {
        let mut vless_config = VlessConfig::new();

        let user_info = parsed.username();
        vless_config.add_user(0, user_info, None).map_err(|e| {
            error!("url to config: vless: user {} invalid, {}", user_info, e);
            UrlParseError::InvalidUserInfo
        })?;

        let mut config = ServerConfig::new(Self::from_url_host(parsed, 8388)?, ServerProtocol::Vless(vless_config));

        if let Some(fragment) = parsed.fragment() {
            config.set_remarks(fragment);
        }

        if let Some(q) = parsed.query() {
            let query = match serde_urlencoded::from_bytes::<Vec<(String, String)>>(q.as_bytes()) {
                Ok(q) => q,
                Err(err) => {
                    error!("url to config: vless: Failed to parse QueryString, err: {}", err);
                    return Err(UrlParseError::InvalidQueryString);
                }
            };

            #[cfg(feature = "transport")]
            {
                if let Some(transport_type) = Self::from_url_get_arg(&query, "type") {
                    match transport_type.as_str() {
                        #[cfg(feature = "transport-ws")]
                        "ws" => {
                            if let Some(security) = Self::from_url_get_arg(&query, "security") {
                                match security.as_str() {
                                    #[cfg(feature = "transport-tls")]
                                    "tls" => {
                                        config.set_connector_transport(Some(TransportConnectorConfig::Wss(
                                            Self::from_url_ws(&query)?,
                                            Self::from_url_tls(&query)?,
                                        )));
                                    }
                                    _ => {
                                        error!("url to config: vless: not support security {}", security);
                                        return Err(UrlParseError::InvalidQueryString);
                                    }
                                }
                            } else {
                                config.set_connector_transport(Some(TransportConnectorConfig::Ws(Self::from_url_ws(
                                    &query,
                                )?)));
                            }
                        }
                        #[cfg(feature = "transport-mkcp")]
                        "kcp" | "mkcp" => {
                            config.set_connector_transport(Some(TransportConnectorConfig::Mkcp(Self::from_url_mkcp(
                                &query,
                            )?)));
                        }
                        #[cfg(feature = "transport-skcp")]
                        "skcp" => {
                            config.set_connector_transport(Some(TransportConnectorConfig::Skcp(Self::from_url_skcp(
                                &query,
                            )?)));
                        }
                        #[cfg(feature = "transport-tls")]
                        "tls" => {
                            config.set_connector_transport(Some(TransportConnectorConfig::Tls(Self::from_url_tls(
                                &query,
                            )?)));
                        }
                        _ => {
                            error!("url to config: vless: not support transport type {}", transport_type);
                            return Err(UrlParseError::InvalidQueryString);
                        }
                    }
                    // parsed.qu
                }
            }
        }

        Ok(config)
    }

    pub(crate) fn to_url_vless(&self, vless_config: &VlessConfig) -> String {
        let mut url = "vless://".to_owned();

        if let Some(user) = vless_config.clients.first() {
            url += user.account.id.to_string().as_str();
            url += "@";
        }

        url += self.addr().to_string().as_str();

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
