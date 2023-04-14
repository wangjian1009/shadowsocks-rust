use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::*;

pub use crate::wg::{IPAddressRange, ItfConfig, KeyBytes, PeerConfig};

impl ServerConfig {
    pub(crate) fn from_url_wg(parsed: &Url) -> Result<ServerConfig, UrlParseError> {
        // wg://144.126.139.41:51888?peer-key=/fng93Xwujo0ESFLdj8sSbvP3qiFLi/wBygnxJLNUBY=&itf-mtu=1420&itf-dns=8.8.8.8&peer-persistent-keepalive=20&itf-key=yDgDh25EIU1F6JfJDeiUq2M/pZYG/v8tXNYBrKVPtFs=&itf-addr=10.10.199.22/32

        println!("xxxxx: url: {}", parsed);
        let mut query = Vec::new();
        if let Some(q) = parsed.query() {
            for item in q.split('&') {
                if item.is_empty() {
                    continue;
                }

                let mut split = item.splitn(2, '=');
                match (split.next(), split.next()) {
                    (Some(key), Some(value)) => {
                        println!("url to config: wg: item {}={}", key, value);
                        query.push((key.to_string(), value.to_string()));
                    }
                    _ => {
                        error!("url to config: wg: no parments");
                        return Err(UrlParseError::InvalidQueryString);
                    }
                }
            }
        } else {
            error!("url to config: wg: no parments");
            return Err(UrlParseError::InvalidQueryString);
        }

        let mtu = if let Some(itf_mtu) = Self::from_url_get_arg(&query[..], "itf-mtu") {
            match itf_mtu.parse::<usize>() {
                Ok(v) => Some(v),
                Err(err) => {
                    error!(err = ?err, "url to config: wg: itf-mtu {} parse error", itf_mtu);
                    return Err(UrlParseError::InvalidQueryString);
                }
            }
        } else {
            None
        };

        let mut dns = vec![];
        for query_item in &query {
            if query_item.0 == "itf-dns" {
                match query_item.1.parse::<IpAddr>() {
                    Ok(v) => dns.push(v),
                    Err(err) => {
                        error!(err = ?err, "url to config: wg: itf-dns {} parse error", query_item.1);
                        return Err(UrlParseError::InvalidQueryString);
                    }
                }
            }
        }

        let itf_addr = match Self::from_url_get_arg(&query, "itf-addr") {
            Some(v) => match v.parse::<IPAddressRange>() {
                Ok(v) => v,
                Err(err) => {
                    error!(err = ?err, "url to config: wg: itf-addr decode error");
                    return Err(UrlParseError::InvalidQueryString);
                }
            },
            None => {
                error!("url to config: wg: itf-addr not configured");
                return Err(UrlParseError::InvalidQueryString);
            }
        };

        let itf_key = match Self::from_url_get_arg(&query, "itf-key") {
            Some(v) => match v.parse::<KeyBytes>() {
                Ok(key) => key,
                Err(err) => {
                    error!(err = ?err, "url to config: wg: itf-key format error");
                    return Err(UrlParseError::InvalidQueryString);
                }
            },
            None => {
                error!("url to config: wg: itf-key not configured");
                return Err(UrlParseError::InvalidQueryString);
            }
        };

        let peer_key = match Self::from_url_get_arg(&query, "peer-key") {
            Some(v) => match v.parse::<KeyBytes>() {
                Ok(key) => key,
                Err(err) => {
                    error!(err = ?err, "url to config: wg: peer-key decode error");
                    return Err(UrlParseError::InvalidQueryString);
                }
            },
            None => {
                error!("url to config: wg: no parments");
                return Err(UrlParseError::InvalidQueryString);
            }
        };

        let mut allowed_ips = Vec::new();
        allowed_ips.push(IPAddressRange {
            address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            network_prefix_length: 0,
        });
        allowed_ips.push(IPAddressRange {
            address: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            network_prefix_length: 0,
        });

        let port = parsed.port().unwrap_or(51820);
        let endpoint = if let Some(host) = parsed.host() {
            match host {
                url::Host::Domain(d) => match d.parse::<IpAddr>() {
                    Ok(addr) => SocketAddr::new(addr, port),
                    Err(_err) => {
                        error!("url to config: wg: host not support domain");
                        return Err(UrlParseError::InvalidQueryString);
                    }
                },
                url::Host::Ipv4(addr) => SocketAddr::new(IpAddr::V4(addr), port),
                url::Host::Ipv6(addr) => SocketAddr::new(IpAddr::V6(addr), port),
            }
        } else {
            error!("url to config: wg: host not configured");
            return Err(UrlParseError::InvalidQueryString);
        };

        let persistent_keep_alive = if let Some(v) = Self::from_url_get_arg(&query, "peer-persistent-keepalive") {
            match v.parse::<usize>() {
                Ok(v) => Some(v),
                Err(err) => {
                    error!(err = ?err, "url to config: wg: peer-persistent-keepalive parse error");
                    return Err(UrlParseError::InvalidQueryString);
                }
            }
        } else {
            None
        };

        let wg_config = Config {
            itf: ItfConfig {
                private_key: itf_key,
                addresses: vec![itf_addr],
                listen_port: None,
                mtu,
                dns,
                dns_search: vec![],
            },
            peers: vec![PeerConfig {
                public_key: peer_key,
                pre_shared_key: None,
                allowed_ips,
                endpoint: Some(endpoint),
                persistent_keep_alive,
            }],
        };

        let mut config = ServerConfig::new(Self::from_url_host(parsed, 51820)?, ServerProtocol::WG(wg_config));

        #[cfg(feature = "transport")]
        if Self::from_url_transport_connector(&query)?.is_some() {
            error!("url to config: wg: not support transport");
            return Err(UrlParseError::InvalidQueryString);
        }

        if let Some(fragment) = parsed.fragment() {
            config.set_remarks(fragment);
        }

        Ok(config)
    }

    pub(crate) fn to_url_wg(&self, _wg_config: &Config) -> String {
        let mut url = "wg://".to_owned();

        if let Some(desc) = self.remarks() {
            url += "#";
            url += desc;
        }

        url
    }
}
