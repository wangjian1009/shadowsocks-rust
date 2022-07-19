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

// fn parse(args: ArgsOs) -> Result<Self, ConfigError> {
//     let mut opts = Options::new();

//     opts.optopt(
//         "c",
//         "config",
//         "Read configuration from a file. Note that command line arguments will override the configuration file",
//         "CONFIG_FILE",
//     );

//     opts.optopt("", "port", "Set the server listening port", "SERVER_PORT");

//     opts.optopt(
//         "",
//         "token",
//         "Set the token for TUIC authentication. This option can be used multiple times to set multiple tokens.",
//         "TOKEN",
//     );

//     opts.optopt(
//         "",
//         "certificate",
//         "Set the X.509 certificate. This must be an end-entity certificate",
//         "CERTIFICATE",
//     );

//     opts.optopt("", "private-key", "Set the certificate private key", "PRIVATE_KEY");

//     opts.optopt("", "ip", "Set the server listening IP. Default: 0.0.0.0", "IP");

//     opts.optopt(
//         "",
//         "congestion-controller",
//         r#"Set the congestion control algorithm. Available: "cubic", "new_reno", "bbr". Default: "cubic""#,
//         "CONGESTION_CONTROLLER",
//     );

//     opts.optopt(
//         "",
//         "max-idle-time",
//         "Set the maximum idle time for QUIC connections, in milliseconds. Default: 15000",
//         "MAX_IDLE_TIME",
//     );

//     opts.optopt(
//         "",
//         "authentication-timeout",
//         "Set the maximum time allowed between a QUIC connection established and the TUIC authentication packet received, in milliseconds. Default: 1000",
//         "AUTHENTICATION_TIMEOUT",
//     );

//     opts.optopt(
//         "",
//         "alpn",
//         "Set ALPN protocols that the server accepts. This option can be used multiple times to set multiple ALPN protocols. If not set, the server will not check ALPN at all",
//         "ALPN_PROTOCOL",
//     );

//     opts.optopt(
//         "",
//         "max-udp-relay-packet-size",
//         "UDP relay mode QUIC can transmit UDP packets larger than the MTU. Set this to a higher value allows outbound to receive larger UDP packet. Default: 1500",
//         "MAX_UDP_RELAY_PACKET_SIZE",
//     );

//     opts.optopt(
//         "",
//         "log-level",
//         r#"Set the log level. Available: "off", "error", "warn", "info", "debug", "trace". Default: "info""#,
//         "LOG_LEVEL",
//     );

//     opts.optflag("v", "version", "Print the version");
//     opts.optflag("h", "help", "Print this help menu");

//     let matches = opts.parse(args.skip(1))?;

//     if matches.opt_present("help") {
//         return Err(ConfigError::Help(opts.usage(env!("CARGO_PKG_NAME"))));
//     }

//     if matches.opt_present("version") {
//         return Err(ConfigError::Version(env!("CARGO_PKG_VERSION")));
//     }

//     if !matches.free.is_empty() {
//         return Err(ConfigError::UnexpectedArguments(matches.free.join(", ")));
//     }

//     let port = matches.opt_str("port").map(|port| port.parse());
//     let token = matches.opt_strs("token");
//     let certificate = matches.opt_str("certificate");
//     let private_key = matches.opt_str("private-key");

//     let mut raw = if let Some(path) = matches.opt_str("config") {
//         let mut raw = RawConfig::from_file(path)?;

//         raw.port = Some(
//             port.transpose()?
//                 .or(raw.port)
//                 .ok_or(ConfigError::MissingOption("port"))?,
//         );

//         if !token.is_empty() {
//             raw.token = token;
//         } else if raw.token.is_empty() {
//             return Err(ConfigError::MissingOption("token"));
//         }

//         raw.certificate = Some(
//             certificate
//                 .or(raw.certificate)
//                 .ok_or(ConfigError::MissingOption("certificate"))?,
//         );

//         raw.private_key = Some(
//             private_key
//                 .or(raw.private_key)
//                 .ok_or(ConfigError::MissingOption("private key"))?,
//         );

//         raw
//     } else {
//         RawConfig {
//             port: Some(port.ok_or(ConfigError::MissingOption("port"))??),
//             token: (!token.is_empty())
//                 .then(|| token)
//                 .ok_or(ConfigError::MissingOption("token"))?,
//             certificate: Some(certificate.ok_or(ConfigError::MissingOption("certificate"))?),
//             private_key: Some(private_key.ok_or(ConfigError::MissingOption("private key"))?),
//             ..Default::default()
//         }
//     };

//     if let Some(ip) = matches.opt_str("ip") {
//         raw.ip = ip.parse()?;
//     };

//     if let Some(cgstn_ctrl) = matches.opt_str("congestion-controller") {
//         raw.congestion_controller = cgstn_ctrl.parse()?;
//     };

//     if let Some(timeout) = matches.opt_str("max-idle-time") {
//         raw.max_idle_time = timeout.parse()?;
//     };

//     if let Some(timeout) = matches.opt_str("authentication-timeout") {
//         raw.authentication_timeout = timeout.parse()?;
//     };

//     if let Some(size) = matches.opt_str("max-udp-relay-packet-size") {
//         raw.max_udp_relay_packet_size = size.parse()?;
//     };

//     let alpn = matches.opt_strs("alpn");

//     if !alpn.is_empty() {
//         raw.alpn = alpn;
//     }

//     if let Some(log_level) = matches.opt_str("log-level") {
//         raw.log_level = log_level.parse()?;
//     };

//     Ok(raw)
// }
