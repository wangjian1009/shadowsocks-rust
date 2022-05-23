use super::*;

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
