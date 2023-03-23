use std::{
    io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

pub const WG_KEY_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub itf: ItfConfig,
    pub peers: Vec<PeerConfig>,
}

impl Config {
    pub fn uapi_configuration(&self) -> String {
        let mut wg_settings: Vec<String> = Vec::new();
        wg_settings.push(format!("private_key={}", hex::encode(self.itf.private_key).as_str()));

        if let Some(listen_port) = self.itf.listen_port {
            wg_settings.push(format!("listen_port={}", listen_port));
        }
        if self.peers.len() > 0 {
            wg_settings.push("replace_peers=true".to_string());
        }

        for peer in &self.peers {
            wg_settings.push(format!("public_key={}", hex::encode(peer.public_key)));
            if let Some(pre_shared_key) = peer.pre_shared_key {
                wg_settings.push(format!("preshared_key={}", hex::encode(pre_shared_key).as_str()));
            }

            if let Some(endpoint) = peer.endpoint {
                wg_settings.push(format!("endpoint={}", endpoint));
            }

            if let Some(persistent_keep_alive) = peer.persistent_keep_alive {
                wg_settings.push(format!("persistent_keepalive_interval={}", persistent_keep_alive));
            }

            if peer.allowed_ips.len() > 0 {
                wg_settings.push("replace_allowed_ips=true".to_string());
            }

            for allow_ip in &peer.allowed_ips {
                wg_settings.push(format!("allowed_ip={}", allow_ip));
            }
        }
        wg_settings.join("\n")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ItfConfig {
    pub private_key: [u8; WG_KEY_LEN],
    pub addresses: Vec<IPAddressRange>,
    pub listen_port: Option<usize>,
    pub mtu: Option<usize>,
    pub dns: Vec<IpAddr>,
    pub dns_search: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PeerConfig {
    pub public_key: [u8; WG_KEY_LEN],
    pub pre_shared_key: Option<[u8; WG_KEY_LEN]>,
    pub allowed_ips: Vec<IPAddressRange>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keep_alive: Option<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IPAddressRange {
    pub address: IpAddr,
    pub network_prefix_length: u16,
}

impl std::fmt::Display for IPAddressRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.network_prefix_length)
    }
}

impl FromStr for IPAddressRange {
    type Err = std::io::Error;

    fn from_str(s: &str) -> std::io::Result<IPAddressRange> {
        let mut sp = s.splitn(2, '/');
        match (sp.next(), sp.next()) {
            (Some(address), Some(len)) => {
                let address = match address.parse::<IpAddr>() {
                    Ok(address) => address,
                    Err(err) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("address format error: {}", err),
                        ))
                    }
                };
                let network_prefix_length = match len.parse::<u16>() {
                    Ok(len) => len,
                    Err(err) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("network_prefix_length {} format error: {}", len, err),
                        ))
                    }
                };

                Ok(IPAddressRange {
                    address,
                    network_prefix_length,
                })
            }
            _ => Err(io::Error::new(io::ErrorKind::Other, "format error")),
        }
    }
}
