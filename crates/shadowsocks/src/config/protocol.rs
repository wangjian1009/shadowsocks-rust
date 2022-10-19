use super::*;

#[derive(Clone, Debug, PartialEq)]
pub enum ServerProtocol {
    SS(ShadowsocksConfig),
    #[cfg(feature = "trojan")]
    Trojan(TrojanConfig),
    #[cfg(feature = "vless")]
    Vless(VlessConfig),
    #[cfg(feature = "tuic")]
    Tuic(TuicConfig),
}

impl ServerProtocol {
    pub fn available_protocols() -> &'static [&'static str] {
        &[
            "ss",
            #[cfg(feature = "trojan")]
            "trojan",
            #[cfg(feature = "vless")]
            "vless",
            #[cfg(feature = "tuic")]
            "tuic",
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::SS(..) => "shadowsocks",
            #[cfg(feature = "trojan")]
            Self::Trojan(..) => "trojan",
            #[cfg(feature = "vless")]
            Self::Vless(..) => "vless",
            #[cfg(feature = "tuic")]
            Self::Tuic(..) => "tuic",
        }
    }

    pub fn support_native_packet(&self) -> Option<bool> {
        match self {
            ServerProtocol::SS(..) => None,
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => return Some(false),
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => return Some(false),
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(..) => return Some(true),
        }
    }
}
