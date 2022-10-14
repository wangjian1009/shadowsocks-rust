use quinn::{
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    IdleTimeout, ServerConfig,
};
use rustls::version::TLS13;
use std::{collections::HashSet, io, sync::Arc, time::Duration};

use super::super::CongestionController;
use super::certificate;

#[derive(Clone, Debug, PartialEq)]
pub struct RawConfig {
    pub token: Vec<String>,
    pub certificate: String,
    pub private_key: String,
    pub congestion_controller: CongestionController,
    pub alpn: Vec<String>,
    pub max_udp_relay_packet_size: usize,
}

impl RawConfig {
    pub fn new(certificate: String, private_key: String) -> Self {
        Self {
            token: Vec::new(),
            certificate,
            private_key,
            congestion_controller: CongestionController::Cubic,
            alpn: Vec::new(),
            max_udp_relay_packet_size: 1500,
        }
    }

    pub fn build_tokens(&self) -> HashSet<[u8; 32]> {
        self.token
            .iter()
            .map(|token| *blake3::hash(token.as_bytes()).as_bytes())
            .collect()
    }

    pub fn build_server_config(&self, max_idle_timeout: Duration) -> io::Result<ServerConfig> {
        let certs = certificate::load_certificates(self.certificate.as_str())?;
        let priv_key = certificate::load_private_key(self.private_key.as_str())?;

        let mut crypto = rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        crypto.max_early_data_size = u32::MAX;
        crypto.alpn_protocols = self.alpn.iter().map(|alpn| alpn.clone().into_bytes()).collect();

        let mut config = ServerConfig::with_crypto(Arc::new(crypto));
        let transport = Arc::get_mut(&mut config.transport).unwrap();

        match self.congestion_controller {
            CongestionController::Bbr => {
                transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
            }
            CongestionController::Cubic => {
                transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
            }
            CongestionController::NewReno => {
                transport.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
            }
        }

        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(max_idle_timeout).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
        ));

        Ok(config)
    }
}
