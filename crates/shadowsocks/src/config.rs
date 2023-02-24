//! Configuration

#[cfg(unix)]
use std::path::PathBuf;
use std::{
    collections::HashMap,
    error,
    fmt::{self, Debug, Display},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use byte_string::ByteStr;
use bytes::Bytes;
use cfg_if::cfg_if;
use tracing::error;
use url::{self, Url};

use crate::{
    crypto::{v1::openssl_bytes_to_key, CipherKind},
    plugin::PluginConfig,
    relay::socks5::Address,
};

// 协议配置
mod shadowsocks;
pub use shadowsocks::ShadowsocksConfig;

cfg_if! {
    if #[cfg(feature = "trojan")] {
        mod trojan;
        pub use trojan::TrojanConfig;
    }
}

cfg_if! {
    if #[cfg(feature = "vless")] {
        mod vless;
        pub use crate::vless::{Config as VlessConfig};
    }
}

cfg_if! {
    if #[cfg(feature = "tuic")] {
        mod tuic;

        #[derive(Clone, Debug, PartialEq)]
        pub enum TuicConfig {
            Client(crate::tuic::client::RawConfig),
            Server((crate::tuic::server::RawConfig, bool)),
        }
    }
}

mod protocol;
pub use protocol::{ServerProtocol, ServerProtocolType};

// 传输配置
cfg_if! {
    if #[cfg(feature = "transport")] {
        mod transport;
        pub use transport::{TransportType, TransportConnectorConfig, TransportAcceptorConfig, available_transports};
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

/// Server's user
#[derive(Clone, PartialEq)]
pub struct ServerUser {
    name: String,
    key: Bytes,
    identity_hash: Bytes,
}

impl Debug for ServerUser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerUser")
            .field("name", &self.name)
            .field("key", &STANDARD.encode(&self.key))
            .field("identity_hash", &ByteStr::new(&self.identity_hash))
            .finish()
    }
}

impl ServerUser {
    /// Create a user
    pub fn new<N, K>(name: N, key: K) -> ServerUser
    where
        N: Into<String>,
        K: Into<Bytes>,
    {
        let name = name.into();
        let key = key.into();

        let hash = blake3::hash(&key);
        let identity_hash = Bytes::from(hash.as_bytes()[0..16].to_owned());

        ServerUser {
            name,
            key,
            identity_hash,
        }
    }

    /// Name of the user
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Encryption key of user
    pub fn key(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// User's identity hash
    ///
    /// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
    pub fn identity_hash(&self) -> &[u8] {
        self.identity_hash.as_ref()
    }

    /// User's identity hash
    ///
    /// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
    pub fn clone_identity_hash(&self) -> Bytes {
        self.identity_hash.clone()
    }
}

/// Server multi-users manager
#[derive(Clone, Debug, PartialEq)]
pub struct ServerUserManager {
    users: HashMap<Bytes, Arc<ServerUser>>,
}

impl ServerUserManager {
    /// Create a new manager
    pub fn new() -> ServerUserManager {
        ServerUserManager { users: HashMap::new() }
    }

    /// Add a new user
    pub fn add_user(&mut self, user: ServerUser) {
        self.users.insert(user.clone_identity_hash(), Arc::new(user));
    }

    /// Get user by hash key
    pub fn get_user_by_hash(&self, user_hash: &[u8]) -> Option<&ServerUser> {
        self.users.get(user_hash).map(AsRef::as_ref)
    }

    /// Get user by hash key cloned
    pub fn clone_user_by_hash(&self, user_hash: &[u8]) -> Option<Arc<ServerUser>> {
        self.users.get(user_hash).cloned()
    }

    /// Number of users
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Iterate users
    pub fn users_iter(&self) -> impl Iterator<Item = &ServerUser> {
        self.users.values().map(|v| v.as_ref())
    }
}

impl Default for ServerUserManager {
    fn default() -> ServerUserManager {
        ServerUserManager::new()
    }
}

/// Configuration for a server
#[derive(Clone, Debug, PartialEq)]
pub struct ServerConfig {
    /// Server address
    addr: ServerAddr,
    /// Handshake timeout (connect)
    timeout: Duration,

    /// Remark (Profile Name), normally used as an identifier of this erver
    remarks: Option<String>,

    /// Weight
    weight: ServerWeight,

    /// 请求超时配置
    request_recv_timeout: Duration,

    /// 空闲超时配置
    idle_timeout: Duration,

    /// 协议配置
    protocol: ServerProtocol,

    /// 传输配置
    #[cfg(feature = "transport")]
    acceptor_transport: Option<TransportAcceptorConfig>,
    #[cfg(feature = "transport")]
    connector_transport: Option<TransportConnectorConfig>,
}

#[cfg(feature = "aead-cipher-2022")]
#[inline]
fn make_derived_key(method: CipherKind, password: &str, enc_key: &mut [u8]) {
    if method.is_aead_2022() {
        // AEAD 2022 password is a base64 form of enc_key
        match STANDARD.decode(password) {
            Ok(v) => {
                if v.len() != enc_key.len() {
                    panic!(
                        "{} is expecting a {} bytes key, but password: {} ({} bytes after decode)",
                        method,
                        enc_key.len(),
                        password,
                        v.len()
                    );
                }
                enc_key.copy_from_slice(&v);
            }
            Err(err) => {
                panic!("{method} password {password} is not base64 encoded, error: {err}");
            }
        }
    } else {
        openssl_bytes_to_key(password.as_bytes(), enc_key);
    }
}

#[cfg(not(feature = "aead-cipher-2022"))]
#[inline]
fn make_derived_key(_method: CipherKind, password: &str, enc_key: &mut [u8]) {
    openssl_bytes_to_key(password.as_bytes(), enc_key);
}

/// Check if method supports Extended Identity Header
///
/// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
#[cfg(feature = "aead-cipher-2022")]
#[inline]
pub fn method_support_eih(method: CipherKind) -> bool {
    matches!(
        method,
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
    )
}

fn password_to_keys<P>(method: CipherKind, password: P) -> (String, Box<[u8]>, Vec<Bytes>)
where
    P: Into<String>,
{
    let password = password.into();

    #[cfg(feature = "aead-cipher-2022")]
    if method_support_eih(method) {
        // Extensible Identity Headers
        // iPSK1:iPSK2:iPSK3:...:uPSK

        let mut identity_keys = Vec::new();

        let mut split_iter = password.rsplit(':');

        let upsk = split_iter.next().expect("uPSK");

        let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
        make_derived_key(method, upsk, &mut enc_key);

        for ipsk in split_iter {
            match STANDARD.decode(ipsk) {
                Ok(v) => {
                    identity_keys.push(Bytes::from(v));
                }
                Err(err) => {
                    panic!("iPSK {ipsk} is not base64 encoded, error: {err}");
                }
            }
        }

        identity_keys.reverse();

        return (upsk.to_owned(), enc_key, identity_keys);
    }

    let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
    make_derived_key(method, &password, &mut enc_key);

    (password, enc_key, Vec::new())
}

impl ServerConfig {
    /// 传输层配置
    #[cfg(not(feature = "transport"))]
    pub fn acceptor_transport_tag(&self) -> &str {
        ""
    }

    #[cfg(not(feature = "transport"))]
    pub fn connector_transport_tag(&self) -> &str {
        ""
    }

    /// 协议层配置
    pub fn protocol(&self) -> &ServerProtocol {
        &self.protocol
    }

    pub fn protocol_mut(&mut self) -> &mut ServerProtocol {
        &mut self.protocol
    }

    pub fn set_protocol(&mut self, protocol: ServerProtocol) {
        self.protocol = protocol;
    }

    /// 接收连接请求超时
    pub fn request_recv_timeout(&self) -> Duration {
        self.request_recv_timeout
    }

    pub fn set_request_recv_timeout(&mut self, timeout: Duration) {
        self.request_recv_timeout = timeout;
    }

    /// 无数据传输超时
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub fn set_idle_timeout(&mut self, idle_timeout: Duration) {
        self.idle_timeout = idle_timeout;
    }

    /// Create a new `ServerConfig`
    pub fn new<A>(addr: A, protocol: ServerProtocol) -> ServerConfig
    where
        A: Into<ServerAddr>,
    {
        ServerConfig {
            addr: addr.into(),
            remarks: None,
            protocol,
            timeout: Duration::from_secs(30),
            weight: ServerWeight::new(),

            request_recv_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(1740),

            #[cfg(feature = "transport")]
            acceptor_transport: None,

            #[cfg(feature = "transport")]
            connector_transport: None,
        }
    }

    /// Set server addr
    pub fn set_addr<A>(&mut self, a: A)
    where
        A: Into<ServerAddr>,
    {
        self.addr = a.into();
    }

    /// Get server address
    pub fn addr(&self) -> &ServerAddr {
        &self.addr
    }

    /// Get server's external address
    pub fn external_addr(&self) -> &ServerAddr {
        match &self.protocol {
            ServerProtocol::SS(config) => config.plugin_addr().unwrap_or(&self.addr),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => &self.addr,
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => &self.addr,
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(..) => &self.addr,
        }
    }

    /// Set timeout
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Timeout
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Get server's remark
    pub fn remarks(&self) -> Option<&str> {
        self.remarks.as_ref().map(AsRef::as_ref)
    }

    /// Set server's remark
    pub fn set_remarks<S>(&mut self, remarks: S)
    where
        S: Into<String>,
    {
        self.remarks = Some(remarks.into());
    }

    /// Get server's balancer weight
    pub fn weight(&self) -> &ServerWeight {
        &self.weight
    }

    /// Set server's balancer weight
    pub fn set_weight(&mut self, weight: ServerWeight) {
        self.weight = weight;
    }

    /// Get URL for QRCode
    /// ```plain
    /// ss:// + base64(method:password@host:port)
    /// ```
    pub fn to_qrcode_url(&self) -> String {
        let config = match &self.protocol {
            ServerProtocol::SS(config) => config,
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(config) => {
                let param = format!("{}@{}", config.password(), self.addr());
                return format!("trojan://{}", URL_SAFE_NO_PAD.encode(param));
            }
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(_config) => {
                // TODO: Loki
                let param = "".to_string();
                return format!("vless://{}", URL_SAFE_NO_PAD.encode(param));
            }
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(_config) => {
                // TODO: Loki
                let param = "".to_string();
                return format!("tuic://{}", URL_SAFE_NO_PAD.encode(param));
            }
        };
        let param = format!("{}:{}@{}", config.method(), config.password(), self.addr());
        format!("ss://{}", URL_SAFE_NO_PAD.encode(param))
    }

    /// Get [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) URL
    pub fn to_url(&self) -> String {
        let config = match &self.protocol {
            ServerProtocol::SS(config) => config,
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(config) => {
                let user_info = config.password().to_string();
                let encoded_user_info = URL_SAFE_NO_PAD.encode(user_info);
                return format!("trojan://{}@{}", encoded_user_info, self.addr());
            }
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(vless_config) => return self.to_url_vless(vless_config),
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(tuic_config) => return self.to_url_tuic(tuic_config),
        };

        cfg_if! {
            if #[cfg(feature = "aead-cipher-2022")] {
                let user_info = if !config.method().is_aead_2022() {
                    let user_info = format!("{}:{}", config.method(), config.password());
                    URL_SAFE_NO_PAD.encode(&user_info)
                } else {
                    format!("{}:{}", config.method(), percent_encoding::utf8_percent_encode(config.password(), percent_encoding::NON_ALPHANUMERIC))
                };
            } else {
                let mut user_info = format!("{}:{}", config.method(), config.password());
                user_info = URL_SAFE_NO_PAD.encode(&user_info)
            }
        }

        let mut url = format!("ss://{}@{}", user_info, self.addr());
        if let Some(c) = self.if_ss(|c| c.plugin()).unwrap_or(None) {
            let mut plugin = c.plugin.clone();
            if let Some(ref opt) = c.plugin_opts {
                plugin += ";";
                plugin += opt;
            }

            url += "/?plugin=";
            for c in percent_encoding::utf8_percent_encode(&plugin, percent_encoding::NON_ALPHANUMERIC) {
                url.push_str(c);
            }
        }

        if let Some(remark) = self.remarks() {
            url += "#";
            for c in percent_encoding::utf8_percent_encode(remark, percent_encoding::NON_ALPHANUMERIC) {
                url.push_str(c);
            }
        }

        url
    }

    /// Parse from [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) URL
    ///
    /// Extended formats:
    ///
    /// 1. QRCode URL supported by shadowsocks-android, https://github.com/shadowsocks/shadowsocks-android/issues/51
    /// 2. Plain userinfo:password format supported by go2-shadowsocks2
    pub fn from_url(encoded: &str) -> Result<ServerConfig, UrlParseError> {
        let parsed = Url::parse(encoded).map_err(UrlParseError::from)?;

        if parsed.scheme() != "ss" {
            #[cfg(feature = "trojan")]
            if parsed.scheme() == "trojan" {
                return Self::from_url_trojan(&parsed);
            }

            #[cfg(feature = "vless")]
            if parsed.scheme() == "vless" {
                return Self::from_url_vless(&parsed);
            }

            #[cfg(feature = "tuic")]
            if parsed.scheme() == "tuic" {
                return Self::from_url_tuic_client(&parsed);
            }

            tracing::error!("not supported protocol {}", parsed.scheme());
            return Err(UrlParseError::InvalidScheme);
        }

        let user_info = parsed.username();
        if user_info.is_empty() {
            // This maybe a QRCode URL, which is ss://BASE64-URL-ENCODE(pass:encrypt@hostname:port)

            let encoded = match parsed.host_str() {
                Some(e) => e,
                None => return Err(UrlParseError::MissingHost),
            };

            let mut decoded_body = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(b) => match String::from_utf8(b) {
                    Ok(b) => b,
                    Err(..) => return Err(UrlParseError::InvalidServerAddr),
                },
                Err(err) => {
                    error!("failed to parse legacy ss://ENCODED with Base64, err: {}", err);
                    return Err(UrlParseError::InvalidServerAddr);
                }
            };

            decoded_body.insert_str(0, "ss://");
            // Parse it like ss://method:password@host:port
            return ServerConfig::from_url(&decoded_body);
        }

        let (method, pwd) = match parsed.password() {
            Some(password) => {
                // Plain method:password without base64 encoded

                let m = match percent_encoding::percent_decode_str(user_info).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!("failed to parse percent-encoded method in userinfo, err: {}", err);
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                let p = match percent_encoding::percent_decode_str(password).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!("failed to parse percent-encoded password in userinfo, err: {}", err);
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                (m, p)
            }
            None => {
                // userinfo is not required to be percent encoded, but some implementation did.
                // If the base64 library have padding = added to the encoded string, then it will become %3D.

                let decoded_user_info = match percent_encoding::percent_decode_str(user_info).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!("failed to parse percent-encoded userinfo, err: {}", err);
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                // reborrow to fit AsRef<[u8]>
                let decoded_user_info: &str = &decoded_user_info;

                let base64_config = if decoded_user_info.ends_with('=') {
                    // Some implementation, like outline,
                    // or those with Python (base64 in Python will still have '=' padding for URL safe encode)
                    URL_SAFE
                } else {
                    URL_SAFE_NO_PAD
                };

                let account = match base64_config.decode(decoded_user_info) {
                    Ok(account) => match String::from_utf8(account) {
                        Ok(ac) => ac,
                        Err(..) => return Err(UrlParseError::InvalidAuthInfo),
                    },
                    Err(err) => {
                        error!("failed to parse UserInfo with Base64, err: {}", err);
                        return Err(UrlParseError::InvalidUserInfo);
                    }
                };

                let mut sp2 = account.splitn(2, ':');
                let (m, p) = match (sp2.next(), sp2.next()) {
                    (Some(m), Some(p)) => (m, p),
                    _ => return Err(UrlParseError::InvalidUserInfo),
                };

                (m.to_owned().into(), p.to_owned().into())
            }
        };

        let host = match parsed.host_str() {
            Some(host) => host,
            None => return Err(UrlParseError::MissingHost),
        };

        let port = parsed.port().unwrap_or(8388);
        let addr = format!("{host}:{port}");

        let addr = match addr.parse::<ServerAddr>() {
            Ok(a) => a,
            Err(err) => {
                error!("failed to parse \"{}\" to ServerAddr, err: {:?}", addr, err);
                return Err(UrlParseError::InvalidServerAddr);
            }
        };

        let method = method.parse().expect("method");
        let mut svrconfig = ServerConfig::new(addr, ServerProtocol::SS(ShadowsocksConfig::new(pwd, method)));

        if let Some(q) = parsed.query() {
            let query = match serde_urlencoded::from_bytes::<Vec<(String, String)>>(q.as_bytes()) {
                Ok(q) => q,
                Err(err) => {
                    error!("failed to parse QueryString, err: {}", err);
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
                        svrconfig.must_be_ss_mut(|c| c.set_plugin(plugin));
                    }
                }
            }
        }

        if let Some(frag) = parsed.fragment() {
            svrconfig.set_remarks(frag);
        }

        Ok(svrconfig)
    }

    /// Check if it is a basic format server
    pub fn is_basic(&self) -> bool {
        self.if_ss(|c| self.remarks().is_none() && c.id().is_none())
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    fn from_url_get_arg<'a>(params: &'a [(String, String)], k: &str) -> Option<&'a String> {
        for item in params.iter() {
            if item.0 == k {
                return Some(&item.1);
            }
        }

        None
    }

    #[allow(dead_code)]
    fn from_url_get_arg_as<T: FromStr>(params: &[(String, String)], k: &str) -> Result<Option<T>, UrlParseError> {
        match Self::from_url_get_arg(params, k) {
            Some(v) => match v.parse::<T>() {
                Ok(v) => Ok(Some(v)),
                Err(_e) => Err(UrlParseError::InvalidQueryString),
            },
            None => Ok(None),
        }
    }

    #[allow(dead_code)]
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

    /// SS是原版协议，经常需要访问，补充辅助函数进行处理
    pub fn must_be_ss_mut<Fn, R>(&mut self, f: Fn) -> R
    where
        Fn: FnOnce(&mut ShadowsocksConfig) -> R,
    {
        match &mut self.protocol {
            ServerProtocol::SS(cfg) => f(cfg),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => unreachable!(),
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => unreachable!(),
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(..) => unreachable!(),
        }
    }

    pub fn if_ss<'a, Fn, R>(&'a self, f: Fn) -> Option<R>
    where
        Fn: FnOnce(&'a ShadowsocksConfig) -> R,
    {
        match &self.protocol {
            ServerProtocol::SS(cfg) => Some(f(cfg)),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => None,
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => None,
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(..) => None,
        }
    }

    pub fn if_ss_mut<'a, Fn, R>(&'a mut self, f: Fn) -> Option<R>
    where
        Fn: FnOnce(&'a mut ShadowsocksConfig) -> R,
    {
        match &mut self.protocol {
            ServerProtocol::SS(cfg) => Some(f(cfg)),
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => None,
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => None,
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(..) => None,
        }
    }

    pub fn if_not_ss(&self) -> bool {
        match &self.protocol {
            ServerProtocol::SS(..) => false,
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => true,
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => true,
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(..) => true,
        }
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
    InvalidSuite,
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
            UrlParseError::InvalidSuite => write!(f, "invalid suite"),
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
            UrlParseError::InvalidSuite => None,
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
            ServerAddr::SocketAddr(ref a) => write!(f, "{a}"),
            ServerAddr::DomainName(ref d, port) => write!(f, "{d}:{port}"),
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
            ManagerAddr::DomainName(ref dname, port) => write!(f, "{dname}:{port}"),
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
    /// Default strategy based on protocol
    ///
    /// SIP022 (AEAD-2022): Reject
    /// SIP004 (AEAD): Ignore
    /// Stream: Ignore
    Default,
    /// Ignore it completely
    Ignore,
    /// Try to detect replay attack and warn about it
    Detect,
    /// Try to detect replay attack and reject the request
    Reject,
}

impl Default for ReplayAttackPolicy {
    fn default() -> ReplayAttackPolicy {
        ReplayAttackPolicy::Default
    }
}

impl Display for ReplayAttackPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReplayAttackPolicy::Default => f.write_str("default"),
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
            "default" => Ok(ReplayAttackPolicy::Default),
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
                    let $connector = $crate::transport::mkcp::MkcpConnector::new(Arc::new(mkcp_config.clone()), None);
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
