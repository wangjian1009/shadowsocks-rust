//! Configuration
#![macro_use]

#[cfg(unix)]
use std::path::PathBuf;
use std::{
    error,
    fmt::{self, Display},
    net::SocketAddr,
    str::FromStr,
    time::Duration,
};

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use log::error;
use url::{self, Url};

use crate::{
    crypto::v1::{openssl_bytes_to_key, CipherKind},
    plugin::PluginConfig,
    relay::socks5::Address,
};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "transport")] {
        mod transport;
        pub use transport::{TransportConnectorConfig, TransportAcceptorConfig, available_transports};
    }
}

cfg_if! {
    if #[cfg(feature = "vless")] {
        pub use crate::vless::{Config as VlessConfig};
    }
}

cfg_if! {
   if #[cfg(feature = "transport-ws")] {
        use crate::transport::websocket::WebSocketConnectorConfig;
        const DEFAULT_SNI: &str = "www.google.com";
    }
}

cfg_if! {
   if #[cfg(feature = "transport-tls")] {
       use crate::transport::tls::TlsConnectorConfig;
   }
}

cfg_if! {
   if #[cfg(feature = "transport-mkcp")] {
       use crate::transport::mkcp::{HeaderConfig, MkcpConfig};
   }
}

cfg_if! {
   if #[cfg(feature = "transport-skcp")] {
       use crate::transport::skcp::SkcpConfig;
   }
}

/// Shadowsocks server type
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServerType {
    /// Running as a local service
    Local,

    /// Running as a shadowsocks server
    Server,
}

impl ServerType {
    /// Check if it is `Local`
    pub fn is_local(self) -> bool {
        self == ServerType::Local
    }

    /// Check if it is `Server`
    pub fn is_server(self) -> bool {
        self == ServerType::Server
    }
}

/// Server mode
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    TcpOnly = 0x01,
    TcpAndUdp = 0x03,
    UdpOnly = 0x02,
}

impl Mode {
    /// Check if UDP is enabled
    pub fn enable_udp(self) -> bool {
        matches!(self, Mode::UdpOnly | Mode::TcpAndUdp)
    }

    /// Check if TCP is enabled
    pub fn enable_tcp(self) -> bool {
        matches!(self, Mode::TcpOnly | Mode::TcpAndUdp)
    }

    /// Merge with another Mode
    pub fn merge(&self, mode: Mode) -> Mode {
        let me = *self as u8;
        let fm = mode as u8;
        match me | fm {
            0x01 => Mode::TcpOnly,
            0x02 => Mode::UdpOnly,
            0x03 => Mode::TcpAndUdp,
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Mode::TcpOnly => f.write_str("tcp_only"),
            Mode::TcpAndUdp => f.write_str("tcp_and_udp"),
            Mode::UdpOnly => f.write_str("udp_only"),
        }
    }
}

impl FromStr for Mode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp_only" => Ok(Mode::TcpOnly),
            "tcp_and_udp" => Ok(Mode::TcpAndUdp),
            "udp_only" => Ok(Mode::UdpOnly),
            _ => Err(()),
        }
    }
}

/// Server's weight
///
/// Commonly for using in balancer
#[derive(Debug, Clone, PartialEq)]
pub struct ServerWeight {
    tcp_weight: f32,
    udp_weight: f32,
}

impl Default for ServerWeight {
    fn default() -> Self {
        ServerWeight::new()
    }
}

impl ServerWeight {
    /// Creates a default weight for server, which will have 1.0 for both TCP and UDP
    pub fn new() -> ServerWeight {
        ServerWeight {
            tcp_weight: 1.0,
            udp_weight: 1.0,
        }
    }

    /// Weight for TCP balancer
    pub fn tcp_weight(&self) -> f32 {
        self.tcp_weight
    }

    /// Set weight for TCP balancer in `[0, 1]`
    pub fn set_tcp_weight(&mut self, weight: f32) {
        assert!((0.0..=1.0).contains(&weight));
        self.tcp_weight = weight;
    }

    /// Weight for UDP balancer
    pub fn udp_weight(&self) -> f32 {
        self.udp_weight
    }

    /// Set weight for UDP balancer in `[0, 1]`
    pub fn set_udp_weight(&mut self, weight: f32) {
        assert!((0.0..=1.0).contains(&weight));
        self.udp_weight = weight;
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ShadowsocksConfig {
    /// Encryption password (key)
    password: String,
    /// Encryption type (method)
    method: CipherKind,
    /// Encryption key
    enc_key: Box<[u8]>,

    /// Plugin config
    plugin: Option<PluginConfig>,
    /// Plugin address
    plugin_addr: Option<ServerAddr>,
}

impl ShadowsocksConfig {
    /// Create a new `ServerConfig`
    pub fn new<P>(password: P, method: CipherKind) -> Self
    where
        P: Into<String>,
    {
        let password = password.into();

        let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
        openssl_bytes_to_key(password.as_bytes(), &mut enc_key);

        ShadowsocksConfig {
            password,
            method,
            enc_key,
            plugin: None,
            plugin_addr: None,
        }
    }

    /// Set plugin
    pub fn set_plugin(&mut self, p: PluginConfig) {
        self.plugin = Some(p);
    }

    /// Get encryption key
    pub fn key(&self) -> &[u8] {
        self.enc_key.as_ref()
    }

    /// Set password
    pub fn set_password(&mut self, password: &str) {
        self.password = password.to_string();

        let mut enc_key = vec![0u8; self.method.key_len()].into_boxed_slice();
        openssl_bytes_to_key(self.password.as_bytes(), &mut enc_key);
        self.enc_key = enc_key;
    }

    /// Get password
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    /// Get method
    pub fn method(&self) -> CipherKind {
        self.method
    }

    /// Set encryption method
    pub fn set_method<P>(&mut self, method: CipherKind, password: P)
    where
        P: Into<String>,
    {
        self.method = method;
        self.password = password.into();

        let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
        openssl_bytes_to_key(self.password.as_bytes(), &mut enc_key);

        self.enc_key = enc_key;
    }

    /// Get plugin
    pub fn plugin(&self) -> Option<&PluginConfig> {
        self.plugin.as_ref()
    }

    /// Set plugin address
    pub fn set_plugin_addr(&mut self, a: ServerAddr) {
        self.plugin_addr = Some(a);
    }

    /// Get plugin address
    pub fn plugin_addr(&self) -> Option<&ServerAddr> {
        self.plugin_addr.as_ref()
    }
}

cfg_if! {
    if #[cfg(feature = "trojan")] {
        use crate::trojan::protocol::{HASH_STR_LEN, password_to_hash};

        #[derive(Clone, Debug, PartialEq)]
        pub struct TrojanConfig {
            password: String,
            hash: [u8; HASH_STR_LEN],
        }

        impl TrojanConfig {
            pub fn new<P>(password: P) -> Self
            where
                P: Into<String>
            {
                use bytes::Buf;

                let password = password.into();
                let mut hash = [0u8; HASH_STR_LEN];
                password_to_hash(password.as_str())
                    .as_bytes()
                    .copy_to_slice(&mut hash);

                TrojanConfig {
                    password,
                    hash,
                }
            }

            /// Set password
            pub fn set_password(&mut self, password: &str) {
                use bytes::Buf;

                self.password = password.to_string();

                password_to_hash(password)
                    .as_bytes()
                    .copy_to_slice(&mut self.hash);
            }

            /// Get password
            pub fn password(&self) -> &str {
                self.password.as_str()
            }

            pub fn hash(&self) -> &[u8; HASH_STR_LEN] {
                &self.hash
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ServerProtocol {
    SS(ShadowsocksConfig),
    #[cfg(feature = "trojan")]
    Trojan(TrojanConfig),
    #[cfg(feature = "vless")]
    Vless(VlessConfig),
}

impl ServerProtocol {
    pub fn available_protocols() -> &'static [&'static str] {
        &[
            "ss",
            #[cfg(feature = "trojan")]
            "trojan",
            #[cfg(feature = "vless")]
            "vless",
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::SS(..) => "shadowsocks",
            #[cfg(feature = "trojan")]
            Self::Trojan(..) => "trojan",
            #[cfg(feature = "vless")]
            Self::Vless(..) => "vless",
        }
    }
}

/// Configuration for a server
#[derive(Clone, Debug, PartialEq)]
pub struct ServerConfig {
    /// Server address
    addr: ServerAddr,
    /// Handshake timeout (connect)
    timeout: Option<Duration>,

    /// Transform
    #[cfg(feature = "transport")]
    acceptor_transport: Option<TransportAcceptorConfig>,

    #[cfg(feature = "transport")]
    connector_transport: Option<TransportConnectorConfig>,

    /// Request recv timeout
    request_recv_timeout: Option<Duration>,

    /// Idle timeout
    idle_timeout: Option<Duration>,

    /// Remark (Profile Name), normally used as an identifier of this erver
    remarks: Option<String>,
    /// ID (SIP008) is a random generated UUID
    id: Option<String>,

    /// Mode
    mode: Mode,

    /// Protocol
    protocol: ServerProtocol,

    /// Weight
    weight: ServerWeight,
}

impl ServerConfig {
    #[cfg(feature = "transport")]
    pub fn acceptor_transport(&self) -> Option<&TransportAcceptorConfig> {
        self.acceptor_transport.as_ref()
    }

    pub fn acceptor_transport_tag(&self) -> &str {
        #[cfg(feature = "transport")]
        match self.acceptor_transport.as_ref() {
            None => "()",
            Some(transport) => match transport {
                #[cfg(feature = "transport-ws")]
                &TransportAcceptorConfig::Ws(..) => "(ws)",
                #[cfg(feature = "transport-tls")]
                &TransportAcceptorConfig::Tls(..) => "(tls)",
                #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
                &TransportAcceptorConfig::Wss(..) => "(wss)",
                #[cfg(feature = "transport-mkcp")]
                &TransportAcceptorConfig::Mkcp(..) => "(mkcp)",
                #[cfg(feature = "transport-skcp")]
                &TransportAcceptorConfig::Skcp(..) => "(skcp)",
            },
        }

        #[cfg(not(feature = "transport"))]
        ""
    }

    /// Get server address
    pub fn addr(&self) -> &ServerAddr {
        &self.addr
    }

    #[cfg(feature = "transport")]
    pub fn connector_transport(&self) -> Option<&TransportConnectorConfig> {
        self.connector_transport.as_ref()
    }

    pub fn connector_transport_tag(&self) -> &str {
        #[cfg(feature = "transport")]
        match self.connector_transport.as_ref() {
            None => "()",
            Some(ref transport) => match transport {
                #[cfg(feature = "transport-ws")]
                &TransportConnectorConfig::Ws(..) => "(ws)",
                #[cfg(feature = "transport-tls")]
                &TransportConnectorConfig::Tls(..) => "(tls)",
                #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
                &TransportConnectorConfig::Wss(..) => "(wss)",
                #[cfg(feature = "transport-mkcp")]
                &TransportConnectorConfig::Mkcp(..) => "(mkcp)",
                #[cfg(feature = "transport-skcp")]
                &TransportConnectorConfig::Skcp(..) => "(skcp)",
            },
        }

        #[cfg(not(feature = "transport"))]
        ""
    }

    /// Get server's external address
    pub fn external_addr(&self) -> &ServerAddr {
        match &self.protocol {
            ServerProtocol::SS(config) => config.plugin_addr.as_ref().unwrap_or(&self.addr),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => &self.addr,
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => &self.addr,
        }
    }

    /// Parse from [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) URL
    pub fn from_url(encoded: &str) -> Result<ServerConfig, UrlParseError> {
        let parsed = Url::parse(encoded).map_err(UrlParseError::from)?;

        match parsed.scheme() {
            "ss" => Self::from_url_ss(&parsed),
            #[cfg(feature = "trojan")]
            "trojan" => Self::from_url_trojan(&parsed),
            #[cfg(feature = "vless")]
            "vless" => Self::from_url_vless(&parsed),
            _ => return Err(UrlParseError::InvalidScheme),
        }
    }

    #[cfg(feature = "vless")]
    fn from_url_vless(parsed: &Url) -> Result<ServerConfig, UrlParseError> {
        let mut vless_config = VlessConfig::new();

        if let Some(fragment) = parsed.fragment() {
            vless_config.decryption = Some(fragment.to_owned());
        }

        let user_info = parsed.username();
        vless_config.add_user(0, user_info, None).map_err(|e| {
            error!("url to config: vless: user {} invalid, {}", user_info, e);
            UrlParseError::InvalidUserInfo
        })?;

        let mut config = ServerConfig::new(Self::from_url_host(parsed, 8388)?, ServerProtocol::Vless(vless_config));

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

    #[allow(dead_code)]
    fn from_url_get_arg<'a>(params: &'a Vec<(String, String)>, k: &str) -> Option<&'a String> {
        for item in params.iter() {
            if item.0 == k {
                return Some(&item.1);
            }
        }

        None
    }

    #[cfg(feature = "trojan")]
    fn from_url_trojan(_parsed: &Url) -> Result<ServerConfig, UrlParseError> {
        Err(UrlParseError::InvalidScheme)
    }

    fn from_url_ss(parsed: &Url) -> Result<ServerConfig, UrlParseError> {
        let user_info = parsed.username();
        let account = match decode_config(user_info, URL_SAFE_NO_PAD) {
            Ok(account) => match String::from_utf8(account) {
                Ok(ac) => ac,
                Err(..) => {
                    return Err(UrlParseError::InvalidAuthInfo);
                }
            },
            Err(err) => {
                error!("Failed to parse UserInfo with Base64, err: {}", err);
                return Err(UrlParseError::InvalidUserInfo);
            }
        };

        let mut sp2 = account.splitn(2, ':');
        let (method, pwd) = match (sp2.next(), sp2.next()) {
            (Some(m), Some(p)) => (m, p),
            _ => return Err(UrlParseError::InvalidUserInfo),
        };

        let addr = Self::from_url_host(parsed, 8388)?;

        let mut svrconfig = ServerConfig::new(
            addr,
            ServerProtocol::SS(ShadowsocksConfig::new(pwd.to_owned(), method.parse().unwrap())),
        );

        if let Some(q) = parsed.query() {
            let query = match serde_urlencoded::from_bytes::<Vec<(String, String)>>(q.as_bytes()) {
                Ok(q) => q,
                Err(err) => {
                    error!("Failed to parse QueryString, err: {}", err);
                    return Err(UrlParseError::InvalidQueryString);
                }
            };

            for (key, value) in query {
                if key != "plugin" {
                    continue;
                }

                let mut vsp = value.splitn(2, ';');
                match vsp.next() {
                    None => {}
                    Some(p) => {
                        let plugin = PluginConfig {
                            plugin: p.to_owned(),
                            plugin_opts: vsp.next().map(ToOwned::to_owned),
                            plugin_args: Vec::new(), // SIP002 doesn't have arguments for plugins
                        };
                        match &mut svrconfig.protocol {
                            ServerProtocol::SS(ssconfig) => ssconfig.set_plugin(plugin),
                            #[cfg(feature = "trojan")]
                            ServerProtocol::Trojan(..) => {}
                            #[cfg(feature = "vless")]
                            ServerProtocol::Vless(..) => {}
                        }
                    }
                }
            }
        }

        Ok(svrconfig)
    }

    #[cfg(feature = "transport-ws")]
    fn from_url_ws(params: &Vec<(String, String)>) -> Result<WebSocketConnectorConfig, UrlParseError> {
        Ok(WebSocketConnectorConfig {
            path: match Self::from_url_get_arg(params, "path") {
                None => "/".to_owned(),
                Some(path) => path.clone(),
            },
            host: match Self::from_url_get_arg(params, "host") {
                None => DEFAULT_SNI.to_owned(),
                Some(path) => path.clone(),
            },
        })
    }

    #[cfg(feature = "transport-mkcp")]
    fn from_url_mkcp(params: &Vec<(String, String)>) -> Result<MkcpConfig, UrlParseError> {
        let mut mkcp_config = MkcpConfig::default();

        if let Some(header_type) = Self::from_url_get_arg(params, "headerType") {
            mkcp_config.header_config = Some(header_type.parse::<HeaderConfig>().map_err(|_e| {
                error!("url to config: mkcp: not support header type {}", header_type);
                UrlParseError::InvalidQueryString
            })?);
        }

        if let Some(seed) = Self::from_url_get_arg(params, "seed") {
            mkcp_config.seed = Some(seed.clone());
        }

        Ok(mkcp_config)
    }

    #[cfg(feature = "transport-skcp")]
    fn from_url_skcp(_params: &Vec<(String, String)>) -> Result<SkcpConfig, UrlParseError> {
        let skcp_config = SkcpConfig::default();
        Ok(skcp_config)
    }

    #[cfg(feature = "transport-tls")]
    fn from_url_tls(params: &Vec<(String, String)>) -> Result<TlsConnectorConfig, UrlParseError> {
        let tls_config = TlsConnectorConfig {
            sni: match Self::from_url_get_arg(params, "sni") {
                None => {
                    error!("url to config: tls: sni not configured");
                    return Err(UrlParseError::InvalidQueryString);
                }
                Some(sni) => sni.clone(),
            },
            cipher: None,
            cert: None,
        };

        Ok(tls_config)
    }

    fn from_url_host(parsed: &Url, dft_port: u16) -> Result<ServerAddr, UrlParseError> {
        let host = match parsed.host_str() {
            Some(host) => host,
            None => return Err(UrlParseError::MissingHost),
        };

        let port = parsed.port().unwrap_or(dft_port);
        let addr = format!("{}:{}", host, port);

        match addr.parse::<ServerAddr>() {
            Ok(a) => Ok(a),
            Err(err) => {
                error!("Failed to parse \"{}\" to ServerAddr, err: {:?}", addr, err);
                Err(UrlParseError::InvalidServerAddr)
            }
        }
    }

    /// Get server's ID (SIP008)
    pub fn id(&self) -> Option<&str> {
        self.id.as_ref().map(AsRef::as_ref)
    }

    /// Idle Timeout
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    /// Check if it is a basic format server
    pub fn is_basic(&self) -> bool {
        self.remarks.is_none() && self.id.is_none()
    }

    /// Get server's `Mode`
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Create a new `ServerConfig`
    pub fn new<A>(addr: A, protocol: ServerProtocol) -> ServerConfig
    where
        A: Into<ServerAddr>,
    {
        ServerConfig {
            addr: addr.into(),
            protocol,
            timeout: None,
            request_recv_timeout: None,
            idle_timeout: None,
            remarks: None,
            id: None,
            mode: Mode::TcpAndUdp, // Server serves TCP & UDP by default
            weight: ServerWeight::new(),

            #[cfg(feature = "transport")]
            acceptor_transport: None,

            #[cfg(feature = "transport")]
            connector_transport: None,
        }
    }

    pub fn protocol(&self) -> &ServerProtocol {
        &self.protocol
    }

    pub fn protocol_mut(&mut self) -> &mut ServerProtocol {
        &mut self.protocol
    }

    /// Set plugin address
    pub fn set_plugin_addr(&mut self, a: ServerAddr) {
        match &mut self.protocol {
            ServerProtocol::SS(ref mut cfg) => cfg.set_plugin_addr(a),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => {}
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => {}
        }
    }

    /// Get plugin address
    pub fn plugin_addr(&self) -> Option<&ServerAddr> {
        match &self.protocol {
            ServerProtocol::SS(cfg) => cfg.plugin_addr(),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => None,
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => None,
        }
    }

    /// Set plugin
    pub fn set_plugin(&mut self, p: PluginConfig) {
        match &mut self.protocol {
            ServerProtocol::SS(ref mut cfg) => cfg.set_plugin(p),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => {}
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => {}
        }
    }

    pub fn plugin(&self) -> Option<&PluginConfig> {
        match &self.protocol {
            ServerProtocol::SS(cfg) => cfg.plugin.as_ref(),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => None,
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => None,
        }
    }

    /// Get server's remark
    pub fn remarks(&self) -> Option<&str> {
        self.remarks.as_ref().map(AsRef::as_ref)
    }

    /// Request Recv Timeout
    pub fn request_recv_timeout(&self) -> Option<Duration> {
        self.request_recv_timeout
    }

    #[cfg(feature = "transport")]
    pub fn set_acceptor_transport(&mut self, transport: Option<TransportAcceptorConfig>) {
        self.acceptor_transport = transport;
    }

    /// Set server addr
    pub fn set_addr<A>(&mut self, a: A)
    where
        A: Into<ServerAddr>,
    {
        self.addr = a.into();
    }

    #[cfg(feature = "transport")]
    pub fn set_connector_transport(&mut self, transport: Option<TransportConnectorConfig>) {
        self.connector_transport = transport;
    }

    /// Set server's ID (SIP008)
    pub fn set_id<S>(&mut self, id: S)
    where
        S: Into<String>,
    {
        self.id = Some(id.into())
    }

    /// Set Idle Timeout
    pub fn set_idle_timeout(&mut self, idle_timeout: Duration) {
        self.idle_timeout = Some(idle_timeout);
    }

    /// Set server's `Mode`
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub fn set_protocol(&mut self, protocol: ServerProtocol) {
        self.protocol = protocol;
    }

    /// Set server's remark
    pub fn set_remarks<S>(&mut self, remarks: S)
    where
        S: Into<String>,
    {
        self.remarks = Some(remarks.into());
    }

    /// Set Request Recv Timeout
    pub fn set_request_recv_timeout(&mut self, timeout: Duration) {
        self.request_recv_timeout = Some(timeout);
    }

    /// Set timeout
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    /// Set server's balancer weight
    pub fn set_weight(&mut self, weight: ServerWeight) {
        self.weight = weight;
    }

    /// Timeout
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Get URL for QRCode
    /// ```plain
    /// ss:// + base64(method:password@host:port)
    /// ```
    pub fn to_qrcode_url(&self) -> String {
        match &self.protocol {
            ServerProtocol::SS(config) => {
                let param = format!("{}:{}@{}", config.method(), config.password(), self.addr());
                format!("ss://{}", encode_config(&param, URL_SAFE_NO_PAD))
            }
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(config) => {
                let param = format!("{}@{}", config.password(), self.addr());
                format!("trojan://{}", encode_config(&param, URL_SAFE_NO_PAD))
            }
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(_config) => {
                // TODO: Loki
                let param = format!("");
                format!("vless://{}", encode_config(&param, URL_SAFE_NO_PAD))
            }
        }
    }

    #[inline]
    pub fn to_url(&self) -> String {
        match &self.protocol {
            ServerProtocol::SS(config) => self.to_url_ss(config),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(config) => {
                let user_info = format!("{}", config.password());
                let encoded_user_info = encode_config(&user_info, URL_SAFE_NO_PAD);
                format!("trojan://{}@{}", encoded_user_info, self.addr())
            }
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(vless_config) => self.to_url_vless(vless_config),
        }
    }

    /// Get [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) URL
    fn to_url_ss(&self, config: &ShadowsocksConfig) -> String {
        let user_info = format!("{}:{}", config.method(), config.password());
        let encoded_user_info = encode_config(&user_info, URL_SAFE_NO_PAD);

        let mut url = format!("ss://{}@{}", encoded_user_info, self.addr());
        if let Some(c) = self.plugin() {
            let mut plugin = c.plugin.clone();
            if let Some(ref opt) = c.plugin_opts {
                plugin += ";";
                plugin += opt;
            }

            let plugin_param = [("plugin", &plugin)];
            url += "/?";
            url += &serde_urlencoded::to_string(&plugin_param).unwrap();
        }

        url
    }

    #[cfg(feature = "vless")]
    fn to_url_vless(&self, vless_config: &VlessConfig) -> String {
        let mut url = "vless://".to_owned();

        if let Some(user) = vless_config.clients.first() {
            url += user.account.id.to_string().as_str();
            url += "@";
        }

        url += self.addr().to_string().as_str();

        let mut params: Vec<(&str, String)> = vec![];

        #[cfg(feature = "transport")]
        if let Some(transport) = self.connector_transport.as_ref() {
            match transport {
                #[cfg(feature = "transport-ws")]
                TransportConnectorConfig::Ws(ws_config) => {
                    params.push(("type", "ws".to_owned()));
                    params.push(("path", ws_config.path.to_owned()));
                    params.push(("host", ws_config.host.to_owned()));
                }
                #[cfg(feature = "transport-tls")]
                TransportConnectorConfig::Tls(_tls_config) => {}
                #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
                TransportConnectorConfig::Wss(ws_config, tls_config) => {
                    params.push(("type", "ws".to_owned()));
                    params.push(("path", ws_config.path.to_owned()));
                    params.push(("host", ws_config.host.to_owned()));
                    params.push(("security", "tls".to_owned()));
                    params.push(("sni", tls_config.sni.to_owned()));
                }
                #[cfg(feature = "transport-mkcp")]
                TransportConnectorConfig::Mkcp(_mkcp_config) => {
                    params.push(("type", "kcp".to_owned()));
                }
                #[cfg(feature = "transport-skcp")]
                TransportConnectorConfig::Skcp(_skcp_config) => {
                    params.push(("type", "skcp".to_owned()));
                }
            }
        }

        if !params.is_empty() {
            url += "/?";
            url += &serde_urlencoded::to_string(&params).unwrap();
        }

        if let Some(desc) = vless_config.decryption.as_ref() {
            url += "#";
            url += desc;
        }

        url
    }

    /// Get server's balancer weight
    pub fn weight(&self) -> &ServerWeight {
        &self.weight
    }
}

/// Shadowsocks URL parsing Error
#[derive(Debug, Clone)]
pub enum UrlParseError {
    ParseError(url::ParseError),
    InvalidScheme,
    InvalidUserInfo,
    MissingHost,
    InvalidAuthInfo,
    InvalidServerAddr,
    InvalidQueryString,
}

impl From<url::ParseError> for UrlParseError {
    fn from(err: url::ParseError) -> UrlParseError {
        UrlParseError::ParseError(err)
    }
}

impl fmt::Display for UrlParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UrlParseError::ParseError(ref err) => fmt::Display::fmt(err, f),
            UrlParseError::InvalidScheme => write!(f, "URL must have \"ss://\" scheme"),
            UrlParseError::InvalidUserInfo => write!(f, "invalid user info"),
            UrlParseError::MissingHost => write!(f, "missing host"),
            UrlParseError::InvalidAuthInfo => write!(f, "invalid authentication info"),
            UrlParseError::InvalidServerAddr => write!(f, "invalid server address"),
            UrlParseError::InvalidQueryString => write!(f, "invalid query string"),
        }
    }
}

impl error::Error for UrlParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            UrlParseError::ParseError(ref err) => Some(err as &dyn error::Error),
            UrlParseError::InvalidScheme => None,
            UrlParseError::InvalidUserInfo => None,
            UrlParseError::MissingHost => None,
            UrlParseError::InvalidAuthInfo => None,
            UrlParseError::InvalidServerAddr => None,
            UrlParseError::InvalidQueryString => None,
        }
    }
}

impl FromStr for ServerConfig {
    type Err = UrlParseError;

    fn from_str(s: &str) -> Result<ServerConfig, Self::Err> {
        ServerConfig::from_url(s)
    }
}

/// Server address
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServerAddr {
    /// IP Address
    SocketAddr(SocketAddr),
    /// Domain name address, eg. example.com:8080
    DomainName(String, u16),
}

impl ServerAddr {
    /// Get string representation of domain
    pub fn host(&self) -> String {
        match *self {
            ServerAddr::SocketAddr(ref s) => s.ip().to_string(),
            ServerAddr::DomainName(ref dm, _) => dm.clone(),
        }
    }

    /// Get port
    pub fn port(&self) -> u16 {
        match *self {
            ServerAddr::SocketAddr(ref s) => s.port(),
            ServerAddr::DomainName(_, p) => p,
        }
    }

    pub fn is_unspecified(&self) -> bool {
        match *self {
            ServerAddr::SocketAddr(ref s) => s.ip().is_unspecified(),
            ServerAddr::DomainName(..) => false,
        }
    }
}

/// Parse `ServerAddr` error
#[derive(Debug)]
pub struct ServerAddrError;

impl Display for ServerAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ServerAddr")
    }
}

impl FromStr for ServerAddr {
    type Err = ServerAddrError;

    fn from_str(s: &str) -> Result<ServerAddr, ServerAddrError> {
        match s.parse::<SocketAddr>() {
            Ok(addr) => Ok(ServerAddr::SocketAddr(addr)),
            Err(..) => {
                let mut sp = s.split(':');
                match (sp.next(), sp.next()) {
                    (Some(dn), Some(port)) => {
                        if dn.is_empty() {
                            return Err(ServerAddrError);
                        }
                        match port.parse::<u16>() {
                            Ok(port) => Ok(ServerAddr::DomainName(dn.to_owned(), port)),
                            Err(..) => Err(ServerAddrError),
                        }
                    }
                    _ => Err(ServerAddrError),
                }
            }
        }
    }
}

impl Display for ServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ServerAddr::SocketAddr(ref a) => write!(f, "{}", a),
            ServerAddr::DomainName(ref d, port) => write!(f, "{}:{}", d, port),
        }
    }
}

impl From<SocketAddr> for ServerAddr {
    fn from(addr: SocketAddr) -> ServerAddr {
        ServerAddr::SocketAddr(addr)
    }
}

impl<I: Into<String>> From<(I, u16)> for ServerAddr {
    fn from((dname, port): (I, u16)) -> ServerAddr {
        ServerAddr::DomainName(dname.into(), port)
    }
}

impl From<Address> for ServerAddr {
    fn from(addr: Address) -> ServerAddr {
        match addr {
            Address::SocketAddress(sa) => ServerAddr::SocketAddr(sa),
            Address::DomainNameAddress(dn, port) => ServerAddr::DomainName(dn, port),
        }
    }
}

impl From<&Address> for ServerAddr {
    fn from(addr: &Address) -> ServerAddr {
        match *addr {
            Address::SocketAddress(sa) => ServerAddr::SocketAddr(sa),
            Address::DomainNameAddress(ref dn, port) => ServerAddr::DomainName(dn.clone(), port),
        }
    }
}

impl From<ServerAddr> for Address {
    fn from(addr: ServerAddr) -> Address {
        match addr {
            ServerAddr::SocketAddr(sa) => Address::SocketAddress(sa),
            ServerAddr::DomainName(dn, port) => Address::DomainNameAddress(dn, port),
        }
    }
}

impl From<&ServerAddr> for Address {
    fn from(addr: &ServerAddr) -> Address {
        match *addr {
            ServerAddr::SocketAddr(sa) => Address::SocketAddress(sa),
            ServerAddr::DomainName(ref dn, port) => Address::DomainNameAddress(dn.clone(), port),
        }
    }
}

/// Address for Manager server
#[derive(Debug, Clone)]
pub enum ManagerAddr {
    /// IP address
    SocketAddr(SocketAddr),
    /// Domain name address
    DomainName(String, u16),
    /// Unix socket path
    #[cfg(unix)]
    UnixSocketAddr(PathBuf),
}

/// Error for parsing `ManagerAddr`
#[derive(Debug)]
pub struct ManagerAddrError;

impl Display for ManagerAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ManagerAddr")
    }
}

impl FromStr for ManagerAddr {
    type Err = ManagerAddrError;

    fn from_str(s: &str) -> Result<ManagerAddr, ManagerAddrError> {
        match s.find(':') {
            Some(pos) => {
                // Contains a ':' in address, must be IP:Port or Domain:Port
                match s.parse::<SocketAddr>() {
                    Ok(saddr) => Ok(ManagerAddr::SocketAddr(saddr)),
                    Err(..) => {
                        // Splits into Domain and Port
                        let (sdomain, sport) = s.split_at(pos);
                        let (sdomain, sport) = (sdomain.trim(), sport[1..].trim());

                        match sport.parse::<u16>() {
                            Ok(port) => Ok(ManagerAddr::DomainName(sdomain.to_owned(), port)),
                            Err(..) => Err(ManagerAddrError),
                        }
                    }
                }
            }
            #[cfg(unix)]
            None => {
                // Must be a unix socket path
                Ok(ManagerAddr::UnixSocketAddr(PathBuf::from(s)))
            }
            #[cfg(not(unix))]
            None => Err(ManagerAddrError),
        }
    }
}

impl Display for ManagerAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ManagerAddr::SocketAddr(ref saddr) => fmt::Display::fmt(saddr, f),
            ManagerAddr::DomainName(ref dname, port) => write!(f, "{}:{}", dname, port),
            #[cfg(unix)]
            ManagerAddr::UnixSocketAddr(ref path) => fmt::Display::fmt(&path.display(), f),
        }
    }
}

impl From<SocketAddr> for ManagerAddr {
    fn from(addr: SocketAddr) -> ManagerAddr {
        ManagerAddr::SocketAddr(addr)
    }
}

impl<'a> From<(&'a str, u16)> for ManagerAddr {
    fn from((dname, port): (&'a str, u16)) -> ManagerAddr {
        ManagerAddr::DomainName(dname.to_owned(), port)
    }
}

impl From<(String, u16)> for ManagerAddr {
    fn from((dname, port): (String, u16)) -> ManagerAddr {
        ManagerAddr::DomainName(dname, port)
    }
}

#[cfg(unix)]
impl From<PathBuf> for ManagerAddr {
    fn from(p: PathBuf) -> ManagerAddr {
        ManagerAddr::UnixSocketAddr(p)
    }
}

/// Policy for handling replay attack requests
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReplayAttackPolicy {
    /// Ignore it completely
    Ignore,
    /// Try to detect replay attack and warn about it
    Detect,
    /// Try to detect replay attack and reject the request
    Reject,
}

impl Default for ReplayAttackPolicy {
    fn default() -> ReplayAttackPolicy {
        ReplayAttackPolicy::Ignore
    }
}

impl Display for ReplayAttackPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReplayAttackPolicy::Ignore => f.write_str("ignore"),
            ReplayAttackPolicy::Detect => f.write_str("detect"),
            ReplayAttackPolicy::Reject => f.write_str("reject"),
        }
    }
}

/// Error while parsing ReplayAttackPolicy from string
#[derive(Debug, Clone, Copy)]
pub struct ReplayAttackPolicyError;

impl Display for ReplayAttackPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ReplayAttackPolicy")
    }
}

impl FromStr for ReplayAttackPolicy {
    type Err = ReplayAttackPolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ignore" => Ok(ReplayAttackPolicy::Ignore),
            "detect" => Ok(ReplayAttackPolicy::Detect),
            "reject" => Ok(ReplayAttackPolicy::Reject),
            _ => Err(ReplayAttackPolicyError),
        }
    }
}

#[macro_export]
macro_rules! create_connector_then {
    ($context:expr, $connector_cfg:expr, |$connector:ident| $body:block) => {{
        #[cfg(feature = "transport")]
        match $connector_cfg {
            Some(transport) => match transport {
                #[cfg(feature = "transport-ws")]
                &shadowsocks::config::TransportConnectorConfig::Ws(ref ws_config) => {
                    let $connector = shadowsocks::transport::direct::TcpConnector::new($context);
                    match shadowsocks::transport::websocket::WebSocketConnector::new(ws_config, $connector) {
                        Ok($connector) => $body,
                        Err(err) => Err(err),
                    }
                }
                #[cfg(feature = "transport-tls")]
                &shadowsocks::config::TransportConnectorConfig::Tls(ref tls_config) => {
                    let $connector = shadowsocks::transport::direct::TcpConnector::new($context);
                    match shadowsocks::transport::tls::TlsConnector::new(tls_config, $connector) {
                        Ok($connector) => $body,
                        Err(err) => Err(err),
                    }
                }
                #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
                &shadowsocks::config::TransportConnectorConfig::Wss(ref ws_config, ref tls_config) => {
                    let $connector = shadowsocks::transport::direct::TcpConnector::new($context);
                    match shadowsocks::transport::tls::TlsConnector::new(tls_config, $connector) {
                        Ok($connector) => {
                            match shadowsocks::transport::websocket::WebSocketConnector::new(ws_config, $connector) {
                                Ok($connector) => $body,
                                Err(err) => Err(err),
                            }
                        }
                        Err(err) => Err(err),
                    }
                }
                #[cfg(feature = "transport-mkcp")]
                &shadowsocks::config::TransportConnectorConfig::Mkcp(ref mkcp_config) => {
                    let $connector = shadowsocks::transport::direct::TcpConnector::new($context);
                    let $connector =
                        $crate::transport::mkcp::MkcpConnector::new(Arc::new(mkcp_config.clone()), $connector, None);
                    $body
                }
                #[cfg(feature = "transport-skcp")]
                &shadowsocks::config::TransportConnectorConfig::Skcp(ref skcp_config) => {
                    let $connector =
                        $crate::transport::skcp::SkcpConnector::new($context, Arc::new(skcp_config.clone()));
                    $body
                }
            },
            None => {
                let $connector = shadowsocks::transport::direct::TcpConnector::new($context);
                $body
            }
        }

        #[cfg(not(feature = "transport"))]
        {
            let $connector = shadowsocks::transport::direct::TcpConnector::new($context);
            $body
        }
    }};
}

#[cfg(test)]
mod test;
