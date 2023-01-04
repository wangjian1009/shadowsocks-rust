use super::*;

use lazy_static::lazy_static;
use regex::Regex;
use std::{fmt, str::FromStr};

#[cfg(feature = "transport-ws")]
use crate::transport::websocket::{WebSocketAcceptorConfig, WebSocketConnectorConfig};

#[cfg(feature = "transport-ws")]
pub const DEFAULT_SNI: &str = "www.google.com";

#[cfg(feature = "transport-tls")]
use crate::transport::tls::{TlsAcceptorConfig, TlsConnectorConfig};

#[cfg(any(feature = "transport-mkcp", feature = "transport-skcp"))]
use crate::transport::{HeaderConfig, SecurityConfig};

#[cfg(feature = "transport-mkcp")]
use crate::transport::mkcp::MkcpConfig;

#[cfg(feature = "transport-skcp")]
use crate::transport::skcp::{KcpNoDelayConfig, SkcpConfig};

impl ServerConfig {
    /// 接受客户端的传输配置
    pub fn set_acceptor_transport(&mut self, transport: Option<TransportAcceptorConfig>) {
        self.acceptor_transport = transport;
    }

    pub fn acceptor_transport(&self) -> Option<&TransportAcceptorConfig> {
        self.acceptor_transport.as_ref()
    }

    pub fn acceptor_transport_tag(&self) -> &str {
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
    }

    /// 连接服务器的传输配置
    pub fn set_connector_transport(&mut self, transport: Option<TransportConnectorConfig>) {
        self.connector_transport = transport;
    }

    pub fn connector_transport(&self) -> Option<&TransportConnectorConfig> {
        self.connector_transport.as_ref()
    }

    pub fn connector_transport_tag(&self) -> &str {
        match self.connector_transport.as_ref() {
            None => "()",
            Some(transport) => match transport {
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
    }

    pub(crate) fn from_url_transport_connector(
        query: &[(String, String)],
    ) -> Result<Option<TransportConnectorConfig>, UrlParseError> {
        let transport_type = match Self::from_url_get_arg(query, "type") {
            Some(transport_type) => transport_type,
            None => return Ok(None),
        };

        match transport_type.as_str() {
            #[cfg(feature = "transport-ws")]
            "ws" => {
                if let Some(security) = Self::from_url_get_arg(query, "security") {
                    match security.as_str() {
                        #[cfg(feature = "transport-tls")]
                        "tls" => Ok(Some(TransportConnectorConfig::Wss(
                            Self::from_url_ws(query)?,
                            Self::from_url_tls(query)?,
                        ))),
                        _ => {
                            error!("url to config: vless: not support security {}", security);
                            Err(UrlParseError::InvalidQueryString)
                        }
                    }
                } else {
                    Ok(Some(TransportConnectorConfig::Ws(Self::from_url_ws(query)?)))
                }
            }
            #[cfg(feature = "transport-mkcp")]
            "kcp" | "mkcp" => Ok(Some(TransportConnectorConfig::Mkcp(Self::from_url_mkcp(query)?))),
            #[cfg(feature = "transport-skcp")]
            "skcp" => Ok(Some(TransportConnectorConfig::Skcp(Self::from_url_skcp(query)?))),
            #[cfg(feature = "transport-tls")]
            "tls" => Ok(Some(TransportConnectorConfig::Tls(Self::from_url_tls(query)?))),
            _ => {
                error!("url to config: vless: not support transport type {}", transport_type);
                Err(UrlParseError::InvalidQueryString)
            }
        }
    }

    pub(crate) fn to_url_transport(params: &mut Vec<(&str, String)>, transport: &TransportConnectorConfig) {
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
            TransportConnectorConfig::Skcp(skcp_config) => {
                params.push(("type", "skcp".to_owned()));
                params.push(("mtu", skcp_config.mtu.to_string()));
                params.push(("nodelay", skcp_config.nodelay.nodelay.to_string()));
                params.push(("interval", skcp_config.nodelay.interval.to_string()));
                params.push(("resend", skcp_config.nodelay.resend.to_string()));
                params.push(("nc", skcp_config.nodelay.nc.to_string()));
                params.push(("wnd-size-send", skcp_config.wnd_size.0.to_string()));
                params.push(("wnd-size-recv", skcp_config.wnd_size.1.to_string()));
                params.push(("session-expire", skcp_config.session_expire.as_secs().to_string()));
                params.push(("flush-write", skcp_config.flush_write.to_string()));
                params.push(("flush-acks-input", skcp_config.flush_acks_input.to_string()));
                params.push(("stream", skcp_config.stream.to_string()));
            }
        }
    }

    #[cfg(feature = "transport-ws")]
    fn from_url_ws(params: &[(String, String)]) -> Result<WebSocketConnectorConfig, UrlParseError> {
        Ok(WebSocketConnectorConfig {
            path: match Self::from_url_get_arg(params, "path") {
                None => "/".to_owned(),
                Some(path) => path.clone(),
            },
            host: match Self::from_url_get_arg(params, "host") {
                None => transport::DEFAULT_SNI.to_owned(),
                Some(path) => path.clone(),
            },
        })
    }

    #[cfg(feature = "transport-mkcp")]
    fn from_url_mkcp(params: &[(String, String)]) -> Result<MkcpConfig, UrlParseError> {
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
    fn from_url_skcp(params: &[(String, String)]) -> Result<SkcpConfig, UrlParseError> {
        let params = params.iter().map(|e| (e.0.as_str(), e.1.as_str())).collect();
        match transport::build_skcp_config(&Some(params)) {
            Ok(c) => Ok(c),
            Err(e) => {
                error!("url to config: skcp: {}", e);
                Err(UrlParseError::InvalidQueryString)
            }
        }
    }

    #[cfg(feature = "transport-tls")]
    fn from_url_tls(params: &[(String, String)]) -> Result<TlsConnectorConfig, UrlParseError> {
        let mut cipher_names = None;
        for item in params.iter() {
            if item.0 != "cipher" {
                continue;
            }

            // match item.1 {}

            println!("xxxxxxx {}", item.1);
            if cipher_names.as_ref().is_none() {
                cipher_names = Some(Vec::new())
            }

            cipher_names.as_mut().unwrap().push(item.1.clone());
        }

        let ciphers =
            crate::ssl::get_cipher_suite(cipher_names.as_ref().map(|vs| vs.iter().map(|f| f.as_str()).collect()))
                .map_err(|_e| UrlParseError::InvalidAuthInfo)?;

        let tls_config = TlsConnectorConfig {
            sni: match Self::from_url_get_arg(params, "sni") {
                None => {
                    error!("url to config: tls: sni not configured");
                    return Err(UrlParseError::InvalidQueryString);
                }
                Some(sni) => sni.clone(),
            },
            cipher: ciphers,
            cert: None,
        };

        Ok(tls_config)
    }
}

#[cfg(feature = "transport")]
pub const fn available_transports() -> &'static [&'static str] {
    &[
        "none",
        #[cfg(feature = "transport-ws")]
        "ws",
        #[cfg(feature = "transport-tls")]
        "tls",
        #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
        "wss",
        #[cfg(feature = "transport-mkcp")]
        "mkcp",
        #[cfg(feature = "transport-skcp")]
        "skcp",
    ]
}

#[derive(Clone)]
pub enum TransportType {
    #[cfg(feature = "transport-ws")]
    Ws,
    #[cfg(feature = "transport-tls")]
    Tls,
    #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
    Wss,
    #[cfg(feature = "transport-mkcp")]
    Mkcp,
    #[cfg(feature = "transport-skcp")]
    Skcp,
}

impl TransportType {
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "transport-ws")]
            Self::Ws => "ws",
            #[cfg(feature = "transport-tls")]
            Self::Tls => "tss",
            #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
            Self::Wss => "wss",
            #[cfg(feature = "transport-mkcp")]
            Self::Mkcp => "mkcp",
            #[cfg(feature = "transport-skcp")]
            Self::Skcp => "skcp",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TransportConnectorConfig {
    #[cfg(feature = "transport-ws")]
    Ws(WebSocketConnectorConfig),
    #[cfg(feature = "transport-tls")]
    Tls(TlsConnectorConfig),
    #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
    Wss(WebSocketConnectorConfig, TlsConnectorConfig),
    #[cfg(feature = "transport-mkcp")]
    Mkcp(MkcpConfig),
    #[cfg(feature = "transport-skcp")]
    Skcp(SkcpConfig),
}

impl TransportConnectorConfig {
    fn build(
        protocol: &str,
        _host: &Option<&str>,
        _path: &str,
        _args: Option<Vec<(&str, &str)>>,
    ) -> Result<Self, String> {
        match protocol {
            #[cfg(feature = "transport-ws")]
            "ws" => Ok(TransportConnectorConfig::Ws(Self::build_ws_config(_host, _path))),
            #[cfg(feature = "transport-tls")]
            "tls" => Ok(TransportConnectorConfig::Tls(Self::build_tls_config(_host, &_args)?)),
            #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
            "wss" => Ok(TransportConnectorConfig::Wss(
                Self::build_ws_config(_host, _path),
                Self::build_tls_config(_host, &_args)?,
            )),
            #[cfg(feature = "transport-mkcp")]
            "mkcp" => Ok(TransportConnectorConfig::Mkcp(build_mkcp_config(&_args)?)),
            #[cfg(feature = "transport-skcp")]
            "skcp" => Ok(TransportConnectorConfig::Skcp(build_skcp_config(&_args)?)),
            _ => Err(format!("not support transport protocol {}", protocol)),
        }
    }

    pub fn tpe(&self) -> TransportType {
        match self {
            #[cfg(feature = "transport-ws")]
            Self::Ws(..) => TransportType::Ws,
            #[cfg(feature = "transport-tls")]
            Self::Tls(..) => TransportType::Tls,
            #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
            Self::Wss(..) => TransportType::Wss,
            #[cfg(feature = "transport-mkcp")]
            Self::Mkcp(..) => TransportType::Mkcp,
            #[cfg(feature = "transport-skcp")]
            Self::Skcp(..) => TransportType::Skcp,
        }
    }

    pub fn name(&self) -> &'static str {
        self.tpe().name()
    }

    #[cfg(feature = "transport-ws")]
    #[inline]
    fn build_ws_config(host: &Option<&str>, path: &str) -> WebSocketConnectorConfig {
        WebSocketConnectorConfig {
            path: if path.starts_with('/') {
                path.to_owned()
            } else {
                format!("/{}", path)
            },
            host: host.unwrap_or(DEFAULT_SNI).to_owned(),
        }
    }

    #[cfg(feature = "transport-ws")]
    #[inline]
    fn fmt_ws_path(config: &WebSocketConnectorConfig, f: &mut fmt::Formatter) -> fmt::Result {
        if config.path.starts_with('/') {
            write!(f, "{}", &config.path[1..])
        } else {
            write!(f, "{}", config.path)
        }
    }

    #[cfg(feature = "transport-tls")]
    #[inline]
    fn build_tls_config(host: &Option<&str>, args: &Option<Vec<(&str, &str)>>) -> Result<TlsConnectorConfig, String> {
        let mut cipher_names = None;
        if let Some(ciphers) = find_all_arg(args, "cipher") {
            cipher_names = Some(Vec::new());

            for cipher in ciphers {
                cipher_names.as_mut().unwrap().push(cipher.to_string());
            }
        }

        let ciphers =
            crate::ssl::get_cipher_suite(cipher_names.as_ref().map(|vs| vs.iter().map(|f| f.as_str()).collect()))
                .map_err(|e| format!("{:?}", e))?;

        let mut config = TlsConnectorConfig {
            sni: host.unwrap_or(DEFAULT_SNI).to_owned(),
            cipher: ciphers,
            cert: None,
        };

        if let Some(v) = find_arg(args, "cert") {
            config.cert = Some(v.to_owned());
        }

        Ok(config)
    }

    pub fn support_native_packet(&self) -> bool {
        match self {
            #[cfg(feature = "transport-ws")]
            Self::Ws(..) => false,
            #[cfg(feature = "transport-tls")]
            Self::Tls(..) => false,
            #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
            Self::Wss(..) => false,
            #[cfg(feature = "transport-mkcp")]
            Self::Mkcp(..) => false,
            #[cfg(feature = "transport-skcp")]
            Self::Skcp(..) => false,
        }
    }
}

#[cfg(feature = "transport-mkcp")]
fn build_mkcp_config(args: &Option<Vec<(&str, &str)>>) -> Result<MkcpConfig, String> {
    let mut config = MkcpConfig::default();

    if let Some(header) = find_arg(args, "header") {
        let header = header.parse::<HeaderConfig>().map_err(|e| format!("{}", e))?;
        config.header_config = Some(header);
    }

    if let Some(seed) = find_arg(args, "seed") {
        config.seed = Some(seed.to_string());
    }

    Ok(config)
}

#[cfg(feature = "transport-skcp")]
pub fn build_skcp_config(args: &Option<Vec<(&str, &str)>>) -> Result<SkcpConfig, String> {
    use std::time::Duration;
    let mut config = SkcpConfig::default();

    if let Some(mode) = find_arg(args, "mode") {
        match mode {
            "default" => {}
            "fastest" => config.nodelay = KcpNoDelayConfig::fastest(),
            "normal" => config.nodelay = KcpNoDelayConfig::normal(),
            _ => {
                return Err(format!(
                    "skcp: not support mode {}, support default|fastest|normal",
                    mode
                ))
            }
        };
    }

    if let Some(mtu) = find_arg_as::<usize>(args, "mtu")? {
        config.mtu = mtu
    }

    if let Some(nodelay) = find_arg_as::<bool>(args, "nodelay")? {
        config.nodelay.nodelay = nodelay;
    }

    if let Some(interval) = find_arg_as::<i32>(args, "interval")? {
        config.nodelay.interval = interval;
    }

    if let Some(resend) = find_arg_as::<i32>(args, "resend")? {
        config.nodelay.resend = resend;
    }

    if let Some(nc) = find_arg_as::<bool>(args, "nc")? {
        config.nodelay.nc = nc;
    }

    if let Some(wnd_size_send) = find_arg_as::<u16>(args, "wnd-size-send")? {
        config.wnd_size.0 = wnd_size_send;
    }

    if let Some(wnd_size_recv) = find_arg_as::<u16>(args, "wnd-size-recv")? {
        config.wnd_size.1 = wnd_size_recv;
    }

    if let Some(session_expire) = find_arg_as::<u64>(args, "session-expire")? {
        config.session_expire = Duration::from_secs(session_expire);
    }

    if let Some(flush_write) = find_arg_as::<bool>(args, "flush-write")? {
        config.flush_write = flush_write;
    }

    if let Some(flush_acks_input) = find_arg_as::<bool>(args, "flush-acks-input")? {
        config.flush_acks_input = flush_acks_input;
    }

    if let Some(stream) = find_arg_as::<bool>(args, "stream")? {
        config.stream = stream;
    }

    if let Some(header) = find_arg(args, "header") {
        config.header_config = Some(header.parse().map_err(|e| format!("header: {}", e))?);
    }

    if let Some(security) = find_arg(args, "security") {
        config.security_config = Some(match security {
            "simple" => SecurityConfig::Simple,
            "aes-gcm" => {
                if let Some(seed) = find_arg(args, "seed") {
                    SecurityConfig::AESGCM { seed: seed.to_owned() }
                } else {
                    return Err(format!("skcp: not security {}, no seed configured", security));
                }
            }
            _ => {
                return Err(format!(
                    "skcp: not support security {}, support simple|aes-gcm",
                    security
                ))
            }
        });
    }

    Ok(config)
}

impl FromStr for TransportConnectorConfig {
    type Err = String;

    #[inline]
    fn from_str(s: &str) -> Result<Self, String> {
        parse(s, Self::build)
    }
}

impl fmt::Display for TransportConnectorConfig {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "transport-ws")]
            Self::Ws(ref config) => {
                write!(f, "ws://")?;
                Self::fmt_ws_path(config, f)?;
                Ok(())
            }
            #[cfg(feature = "transport-tls")]
            Self::Tls(ref _config) => {
                write!(f, "tls://")?;
                Ok(())
            }
            #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
            Self::Wss(ref ws_config, ref _config) => {
                write!(f, "wss://")?;
                Self::fmt_ws_path(ws_config, f)?;
                Ok(())
            }
            #[cfg(feature = "transport-mkcp")]
            Self::Mkcp(ref _config) => {
                write!(f, "mkcp://")?;
                Ok(())
            }
            #[cfg(feature = "transport-skcp")]
            Self::Skcp(ref _config) => {
                write!(f, "skcp://")?;
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TransportAcceptorConfig {
    #[cfg(feature = "transport-ws")]
    Ws(WebSocketAcceptorConfig),
    #[cfg(feature = "transport-tls")]
    Tls(TlsAcceptorConfig),
    #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
    Wss(WebSocketAcceptorConfig, TlsAcceptorConfig),
    #[cfg(feature = "transport-mkcp")]
    Mkcp(MkcpConfig),
    #[cfg(feature = "transport-skcp")]
    Skcp(SkcpConfig),
}

impl TransportAcceptorConfig {
    pub fn tpe(&self) -> TransportType {
        match self {
            #[cfg(feature = "transport-ws")]
            Self::Ws(..) => TransportType::Ws,
            #[cfg(feature = "transport-tls")]
            Self::Tls(..) => TransportType::Tls,
            #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
            Self::Wss(..) => TransportType::Wss,
            #[cfg(feature = "transport-mkcp")]
            Self::Mkcp(..) => TransportType::Mkcp,
            #[cfg(feature = "transport-skcp")]
            Self::Skcp(..) => TransportType::Skcp,
        }
    }

    #[inline]
    pub fn name(&self) -> &'static str {
        self.tpe().name()
    }

    fn build(
        protocol: &str,
        _host: &Option<&str>,
        _path: &str,
        _args: Option<Vec<(&str, &str)>>,
    ) -> Result<Self, String> {
        match protocol {
            #[cfg(feature = "transport-ws")]
            "ws" => Ok(TransportAcceptorConfig::Ws(Self::build_ws_config(_path))),
            #[cfg(feature = "transport-tls")]
            "tls" => Ok(TransportAcceptorConfig::Tls(Self::build_tls_config(&_args)?)),
            #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
            "wss" => Ok(TransportAcceptorConfig::Wss(
                Self::build_ws_config(_path),
                Self::build_tls_config(&_args)?,
            )),
            #[cfg(feature = "transport-mkcp")]
            "mkcp" => Ok(TransportAcceptorConfig::Mkcp(build_mkcp_config(&_args)?)),
            #[cfg(feature = "transport-skcp")]
            "skcp" => Ok(TransportAcceptorConfig::Skcp(build_skcp_config(&_args)?)),
            _ => Err(format!("not support transport protocol {}", protocol)),
        }
    }

    #[cfg(feature = "transport-ws")]
    #[inline]
    fn build_ws_config(path: &str) -> WebSocketAcceptorConfig {
        WebSocketAcceptorConfig {
            path: if path.starts_with('/') {
                path.to_owned()
            } else {
                format!("/{}", path)
            },
        }
    }

    #[cfg(feature = "transport-ws")]
    fn fmt_ws_path(config: &WebSocketAcceptorConfig, f: &mut fmt::Formatter) -> fmt::Result {
        if config.path.starts_with('/') {
            write!(f, "{}", &config.path[1..])
        } else {
            write!(f, "{}", config.path)
        }
    }

    #[cfg(feature = "transport-tls")]
    fn build_tls_config(args: &Option<Vec<(&str, &str)>>) -> Result<TlsAcceptorConfig, String> {
        let mut cipher_names = None;
        if let Some(ciphers) = find_all_arg(args, "cipher") {
            cipher_names = Some(Vec::new());

            for cipher in ciphers {
                cipher_names.as_mut().unwrap().push(cipher.to_string());
            }
        }

        let ciphers =
            crate::ssl::get_cipher_suite(cipher_names.as_ref().map(|vs| vs.iter().map(|f| f.as_str()).collect()))
                .map_err(|e| format!("{:?}", e))?;

        let config = TlsAcceptorConfig {
            cert: find_arg(args, "cert")
                .ok_or("transport tls cert not configured")?
                .to_owned(),
            key: find_arg(args, "key")
                .ok_or("transport tls key not configured")?
                .to_owned(),
            cipher: ciphers,
        };

        Ok(config)
    }
}

impl FromStr for TransportAcceptorConfig {
    type Err = String;

    #[inline]
    fn from_str(s: &str) -> Result<Self, String> {
        parse(s, Self::build)
    }
}

impl fmt::Display for TransportAcceptorConfig {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "transport-ws")]
            Self::Ws(ref config) => {
                write!(f, "ws://")?;
                Self::fmt_ws_path(config, f)?;
                Ok(())
            }
            #[cfg(feature = "transport-tls")]
            Self::Tls(ref _config) => {
                write!(f, "tls://")?;
                Ok(())
            }
            #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
            Self::Wss(ref ws_config, ref _tls_config) => {
                write!(f, "wss://")?;
                Self::fmt_ws_path(ws_config, f)?;
                Ok(())
            }
            #[cfg(feature = "transport-mkcp")]
            Self::Mkcp(ref _config) => {
                write!(f, "mkcp://")?;
                Ok(())
            }
            #[cfg(feature = "transport-skcp")]
            Self::Skcp(ref skcp_config) => {
                write!(
                    f,
                    "skcp://?mtu={}&nodelay={}&interval={}&resend={}&nc={}&wnd-size-send={}&wnd-size-recv={}&session-expire={}&flush-write={}&flush-acks-input={}&stream={}",
                    skcp_config.mtu,
                    skcp_config.nodelay.nodelay,
                    skcp_config.nodelay.interval,
                    skcp_config.nodelay.resend,
                    skcp_config.nodelay.nc,
                    skcp_config.wnd_size.0,
                    skcp_config.wnd_size.1,
                    skcp_config.session_expire.as_secs(),
                    skcp_config.flush_write,
                    skcp_config.flush_acks_input,
                    skcp_config.stream,
                )?;
                if let Some(header) = skcp_config.header_config.as_ref() {
                    write!(f, "&header={}", header)?;
                }
                if let Some(security) = skcp_config.security_config.as_ref() {
                    match security {
                        SecurityConfig::AESGCM { seed } => write!(f, "&security=aes-gcm&seed={}", seed)?,
                        SecurityConfig::Simple => write!(f, "&security=simple")?,
                    }
                }
                Ok(())
            }
        }
    }
}

fn parse<'a, F, R>(s: &'a str, f: F) -> Result<R, String>
where
    F: FnOnce(&str, &Option<&'a str>, &str, Option<Vec<(&'a str, &'a str)>>) -> Result<R, String>,
{
    lazy_static! {
        static ref RE_URL: Regex = Regex::new(
            r"^(?P<protocol>[\w\d-]+)://(?P<host>[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(:?\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+)?(?P<path>[-\w\d/]*)(:?\?(?P<args>.*))?$"
        )
        .unwrap();
    }

    match RE_URL.captures(s) {
        Some(values) => f(
            &values["protocol"],
            &values.name("host").map(|e| e.as_str()),
            &values["path"],
            values.name("args").map(|e| {
                e.as_str()
                    .split('&')
                    .map(|item| match item.find('=') {
                        Some(pos) => (&item[..pos], &item[pos + 1..]),
                        None => (item, ""),
                    })
                    .collect()
            }),
        ),
        None => Err(format!("format error, input={}", s)),
    }
}

#[allow(unused)]
fn find_arg<'a>(args: &'a Option<Vec<(&str, &str)>>, key: &str) -> Option<&'a str> {
    if let Some(args) = args.as_ref() {
        args.iter().find_map(|(k, v)| if *k == key { Some(*v) } else { None })
    } else {
        None
    }
}

#[allow(unused)]
fn find_arg_as<T: FromStr>(args: &Option<Vec<(&str, &str)>>, key: &str) -> Result<Option<T>, String> {
    match find_arg(args, key) {
        Some(v) => match v.parse::<T>() {
            Ok(v) => Ok(Some(v)),
            Err(e) => Err(format!("{}={} format error", key, v)),
        },
        None => Ok(None),
    }
}

#[allow(unused)]
fn find_all_arg<'a>(args: &'a Option<Vec<(&str, &str)>>, key: &str) -> Option<Vec<&'a str>> {
    let mut results = None;

    if let Some(args) = args.as_ref() {
        args.iter().for_each(|(k, v)| {
            if *k == key {
                if results.is_none() {
                    results = Some(vec![]);
                }
                results.as_mut().unwrap().push(*v);
            }
        });
    }

    results
}

#[cfg(test)]
mod tests;
