use quinn::{
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    ClientConfig, TransportConfig,
};
use rustls::version::TLS13;
use std::{io, str::FromStr, sync::Arc};

use super::super::CongestionController;
use super::{certificate, relay::UdpRelayMode};

pub struct Config {
    pub client_config: ClientConfig,
    pub token_digest: [u8; 32],
    pub udp_relay_mode: UdpRelayMode<(), ()>,
    pub heartbeat_interval: u64,
    pub reduce_rtt: bool,
    pub request_timeout: u64,
    pub max_udp_relay_packet_size: usize,
}

impl Config {
    pub fn new(raw: &RawConfig) -> io::Result<Self> {
        let client_config = {
            let certs = certificate::load_certificates(&raw.certificates)?;

            let mut crypto = rustls::ClientConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&TLS13])
                .map(|b| {
                    if certs.is_empty() {
                        b.with_custom_certificate_verifier(
                            Arc::new(NoVerifier {}) as Arc<dyn rustls::client::ServerCertVerifier>
                        )
                        .with_no_client_auth()
                    } else {
                        b.with_root_certificates(certs).with_no_client_auth()
                    }
                })
                .unwrap();

            crypto.alpn_protocols = raw.alpn.iter().map(|alpn| alpn.clone().into_bytes()).collect();

            crypto.enable_early_data = true;
            crypto.enable_sni = !raw.disable_sni;

            let mut config = ClientConfig::new(Arc::new(crypto));

            let mut transport = TransportConfig::default();
            match raw.congestion_controller {
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

            transport.max_idle_timeout(None);

            config.transport_config(Arc::new(transport));

            config
        };

        let token_digest = *blake3::hash(&raw.token.as_bytes()).as_bytes();
        let udp_relay_mode = raw.udp_relay_mode;
        let heartbeat_interval = raw.heartbeat_interval;
        let reduce_rtt = raw.reduce_rtt;
        let request_timeout = raw.request_timeout;
        let max_udp_relay_packet_size = raw.max_udp_relay_packet_size;

        Ok(Self {
            client_config,
            token_digest,
            udp_relay_mode,
            heartbeat_interval,
            reduce_rtt,
            request_timeout,
            max_udp_relay_packet_size,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RawConfig {
    pub sni: Option<String>,
    pub token: String,
    pub certificates: Vec<String>,
    pub udp_relay_mode: UdpRelayMode<(), ()>,
    pub congestion_controller: CongestionController,
    pub heartbeat_interval: u64,
    pub alpn: Vec<String>,
    pub disable_sni: bool,
    pub reduce_rtt: bool,
    pub request_timeout: u64,
    pub max_udp_relay_packet_size: usize,
}

impl RawConfig {
    pub fn new(token: String) -> Self {
        Self {
            sni: None,
            token,
            certificates: Vec::new(),
            udp_relay_mode: UdpRelayMode::Native(()),
            congestion_controller: CongestionController::Cubic,
            heartbeat_interval: 10000,
            alpn: Vec::new(),
            disable_sni: false,
            reduce_rtt: false,
            request_timeout: 8000,
            max_udp_relay_packet_size: 1500,
        }
    }
}

impl FromStr for UdpRelayMode<(), ()> {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("native") {
            Ok(Self::Native(()))
        } else if s.eq_ignore_ascii_case("quic") {
            Ok(Self::Quic(()))
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("not support UdpRelayMode {}", s),
            ))
        }
    }
}

pub(crate) struct NoVerifier;

impl rustls::client::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
