use super::*;

use crate::tuic::{client, CongestionController};

impl ServerConfig {
    pub(crate) fn from_url_tuic_client(parsed: &Url) -> Result<ServerConfig, UrlParseError> {
        let token = parsed.username();
        if token.is_empty() {
            error!("url to config: tuic: token not configured");
            return Err(UrlParseError::InvalidUserInfo);
        }

        let mut query = None;
        if let Some(q) = parsed.query() {
            query = match serde_urlencoded::from_bytes::<Vec<(String, String)>>(q.as_bytes()) {
                Ok(q) => Some(q),
                Err(err) => {
                    error!("url to config: tuic: Failed to parse QueryString, err: {}", err);
                    return Err(UrlParseError::InvalidQueryString);
                }
            };
        }

        let mut tuic_config = client::RawConfig::new(token.to_owned());
        if let Some(query) = query.as_ref() {
            if let Some(sni) = Self::from_url_get_arg(query, "sni") {
                tuic_config.sni = Some(sni.clone());
            }

            // certificates
            for item in query.iter() {
                if item.0 == "cert" {
                    tuic_config.certificates.push(item.1.to_owned())
                }
            }

            if let Some(udp_relay_mode) =
                Self::from_url_get_arg_as::<client::UdpRelayMode<(), ()>>(query, "udp-relay-mode")?
            {
                tuic_config.udp_relay_mode = udp_relay_mode;
            }

            if let Some(congestion_controller) =
                Self::from_url_get_arg_as::<CongestionController>(query, "congestion-controller")?
            {
                tuic_config.congestion_controller = congestion_controller;
            }

            // alpn
            for item in query.iter() {
                if item.0 == "alpn" {
                    tuic_config.alpn.push(item.1.to_owned())
                }
            }

            if let Some(heartbeat_interval) = Self::from_url_get_arg_as::<u64>(query, "heartbeat-interval")? {
                tuic_config.heartbeat_interval = heartbeat_interval;
            }

            if let Some(disable_sni) = Self::from_url_get_arg_as::<bool>(query, "disable-sni")? {
                tuic_config.disable_sni = disable_sni;
            }

            if let Some(reduce_rtt) = Self::from_url_get_arg_as::<bool>(query, "reduce-rtt")? {
                tuic_config.reduce_rtt = reduce_rtt;
            }

            if let Some(request_timeout) = Self::from_url_get_arg_as::<u64>(query, "request-timeout")? {
                tuic_config.request_timeout = request_timeout;
            }

            // pub max_udp_relay_packet_size: usize,
        }

        let mut config = ServerConfig::new(
            Self::from_url_host(parsed, 443)?,
            ServerProtocol::Tuic(TuicConfig::Client(tuic_config)),
        );

        if let Some(query) = query.as_ref() {
            #[cfg(feature = "transport")]
            if Self::from_url_transport_connector(query)?.is_some() {
                error!("url to config: tuic: not support transport");
                return Err(UrlParseError::InvalidQueryString);
            }
        }

        if let Some(fragment) = parsed.fragment() {
            config.set_remarks(fragment);
        }

        Ok(config)
    }

    pub(crate) fn to_url_tuic(&self, _tuic_config: &TuicConfig) -> String {
        let mut url = "tuic://".to_owned();

        if let Some(desc) = self.remarks() {
            url += "#";
            url += desc;
        }

        url
    }
}
