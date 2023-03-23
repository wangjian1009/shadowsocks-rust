use super::*;

#[derive(Clone)]
pub enum ServerProtocolType {
    SS,
    #[cfg(feature = "trojan")]
    Trojan,
    #[cfg(feature = "vless")]
    Vless,
    #[cfg(feature = "tuic")]
    Tuic,
    #[cfg(feature = "wireguard")]
    WG,
}

impl ServerProtocolType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SS => "shadowsocks",
            #[cfg(feature = "trojan")]
            Self::Trojan => "trojan",
            #[cfg(feature = "vless")]
            Self::Vless => "vless",
            #[cfg(feature = "tuic")]
            Self::Tuic => "tuic",
            #[cfg(feature = "wireguard")]
            Self::WG => "wg",
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
    #[cfg(feature = "tuic")]
    Tuic(TuicConfig),
    #[cfg(feature = "wireguard")]
    WG(Config),
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
            #[cfg(feature = "wireguard")]
            "wg",
        ]
    }

    pub fn tpe(&self) -> ServerProtocolType {
        match self {
            Self::SS(..) => ServerProtocolType::SS,
            #[cfg(feature = "trojan")]
            Self::Trojan(..) => ServerProtocolType::Trojan,
            #[cfg(feature = "vless")]
            Self::Vless(..) => ServerProtocolType::Vless,
            #[cfg(feature = "tuic")]
            Self::Tuic(..) => ServerProtocolType::Tuic,
            #[cfg(feature = "wireguard")]
            Self::WG(..) => ServerProtocolType::WG,
        }
    }

    pub fn name(&self) -> &'static str {
        self.tpe().name()
    }

    pub fn support_native_packet(&self) -> Option<bool> {
        match self {
            ServerProtocol::SS(..) => None,
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => Some(false),
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => Some(false),
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(..) => Some(true),
            #[cfg(feature = "wireguard")]
            ServerProtocol::WG(..) => Some(true),
        }
    }
}
