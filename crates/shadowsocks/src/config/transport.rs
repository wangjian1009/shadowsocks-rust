use lazy_static::lazy_static;
use regex::Regex;
use std::{fmt, str::FromStr};

use crate::transport;

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
    ]
}

#[cfg(feature = "transport-ws")]
use transport::websocket::{WebSocketAcceptorConfig, WebSocketConnectorConfig};

#[cfg(feature = "transport-ws")]
use super::DEFAULT_SNI;

#[cfg(feature = "transport-tls")]
use transport::tls::{TlsAcceptorConfig, TlsConnectorConfig};

#[cfg(feature = "transport-mkcp")]
use transport::mkcp::{HeaderConfig, MkcpConfig};

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
            _ => Err(format!("not support transport protocol {}", protocol)),
        }
    }

    #[cfg(feature = "transport-ws")]
    #[inline]
    fn build_ws_config(host: &Option<&str>, path: &str) -> WebSocketConnectorConfig {
        WebSocketConnectorConfig {
            path: if path.starts_with("/") {
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
        if config.path.starts_with("/") {
            write!(f, "{}", &config.path[1..])
        } else {
            write!(f, "{}", config.path)
        }
    }

    #[cfg(feature = "transport-tls")]
    #[inline]
    fn build_tls_config(host: &Option<&str>, args: &Option<Vec<(&str, &str)>>) -> Result<TlsConnectorConfig, String> {
        let mut config = TlsConnectorConfig {
            sni: host.unwrap_or(DEFAULT_SNI).to_owned(),
            cipher: None,
            cert: None,
        };

        find_arg(args, "cert").map(|v| config.cert = Some(v.to_owned()));
        find_all_arg(args, "cipher").map(|cipher| config.cipher = Some(cipher.iter().map(|c| c.to_string()).collect()));
        Ok(config)
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
}

impl TransportAcceptorConfig {
    pub fn protocol_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "transport-ws")]
            Self::Ws(..) => "ws",
            #[cfg(feature = "transport-tls")]
            Self::Tls(..) => "tls",
            #[cfg(all(feature = "transport-ws", feature = "transport-tls"))]
            Self::Wss(..) => "wss",
            #[cfg(feature = "transport-mkcp")]
            Self::Mkcp(..) => "mkcp",
        }
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
            _ => Err(format!("not support transport protocol {}", protocol)),
        }
    }

    #[cfg(feature = "transport-ws")]
    #[inline]
    fn build_ws_config(path: &str) -> WebSocketAcceptorConfig {
        WebSocketAcceptorConfig {
            path: if path.starts_with("/") {
                path.to_owned()
            } else {
                format!("/{}", path)
            },
        }
    }

    #[cfg(feature = "transport-ws")]
    fn fmt_ws_path(config: &WebSocketAcceptorConfig, f: &mut fmt::Formatter) -> fmt::Result {
        if config.path.starts_with("/") {
            write!(f, "{}", &config.path[1..])
        } else {
            write!(f, "{}", config.path)
        }
    }

    #[cfg(feature = "transport-tls")]
    fn build_tls_config(args: &Option<Vec<(&str, &str)>>) -> Result<TlsAcceptorConfig, String> {
        let mut config = TlsAcceptorConfig {
            cert: find_arg(args, "cert")
                .ok_or_else(|| "transport tls cert not configured")?
                .to_owned(),
            key: find_arg(args, "key")
                .ok_or_else(|| "transport tls key not configured")?
                .to_owned(),
            cipher: None,
        };

        find_all_arg(args, "cipher").map(|cipher| config.cipher = Some(cipher.iter().map(|c| c.to_string()).collect()));

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
