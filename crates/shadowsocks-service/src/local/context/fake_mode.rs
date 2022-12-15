use super::*;

#[derive(Debug, Clone)]
pub enum FakeMode {
    None,
    Bypass,
    ParamError,
}

const S_SS_PASSWORD: [u8; 8] = [112, 23, 191, 57, 112, 36, 251, 217];

#[cfg(feature = "trojan")]
const S_TROJAN_PASSWORD: [u8; 8] = [112, 23, 191, 57, 112, 36, 251, 217];

#[cfg(feature = "vless")]
const S_VLESS_TOKEN: [u8; 16] = [112, 20, 189, 60, 116, 35, 253, 208, 120, 28, 181, 52, 124, 43, 245, 200];

#[cfg(feature = "tuic")]
const S_TUIC_TOKEN: [u8; 8] = [112, 23, 191, 57, 112, 36, 251, 217];

impl FakeMode {
    pub fn is_bypass(&self) -> bool {
        match self {
            FakeMode::Bypass => true,
            _ => false,
        }
    }

    pub fn is_param_error_for_ss(
        &self,
        cfg: &shadowsocks::config::ShadowsocksConfig,
    ) -> Option<shadowsocks::config::ShadowsocksConfig> {
        match self {
            FakeMode::ParamError => {
                let mut new_cfg = cfg.clone();
                new_cfg.set_password(string_decode(&S_SS_PASSWORD).as_str());
                Some(new_cfg)
            }
            _ => None,
        }
    }

    #[cfg(feature = "trojan")]
    pub fn is_param_error_for_trojan(
        &self,
        cfg: &shadowsocks::config::TrojanConfig,
    ) -> Option<shadowsocks::config::TrojanConfig> {
        match self {
            FakeMode::ParamError => {
                let mut new_cfg = cfg.clone();
                new_cfg.set_password(string_decode(&S_TROJAN_PASSWORD).as_str());
                Some(new_cfg)
            }
            _ => None,
        }
    }

    #[cfg(feature = "vless")]
    pub fn is_param_error_for_vless(
        &self,
        cfg: &shadowsocks::config::VlessConfig,
    ) -> Option<shadowsocks::config::VlessConfig> {
        match self {
            FakeMode::ParamError => {
                let mut new_cfg = cfg.clone();

                for client in new_cfg.clients.iter_mut() {
                    client.account.id =
                        shadowsocks::vless::UUID::parse_bytes(string_decode(&S_VLESS_TOKEN).as_bytes()).unwrap();
                }

                Some(new_cfg)
            }
            _ => None,
        }
    }

    #[cfg(feature = "tuic")]
    pub fn is_param_error_for_tuic(
        &self,
        cfg: &shadowsocks::config::TuicConfig,
    ) -> Option<shadowsocks::config::TuicConfig> {
        match self {
            FakeMode::ParamError => match cfg {
                shadowsocks::config::TuicConfig::Client(cfg) => {
                    let mut new_cfg = cfg.clone();
                    new_cfg.token = string_decode(&S_TUIC_TOKEN);
                    Some(shadowsocks::config::TuicConfig::Client(new_cfg))
                }
                shadowsocks::config::TuicConfig::Server(..) => unreachable!(),
            },
            _ => None,
        }
    }
}

impl ServiceContext {
    pub fn fake_mode(&self) -> FakeMode {
        self.fake_mode.clone()
    }

    pub fn set_fake_mode(&mut self, mode: FakeMode) {
        let need_close = match self.fake_mode {
            FakeMode::None => false,
            _ => true,
        };

        self.fake_mode = mode;

        if need_close {
            self.close_connections();
        }
    }
}

const S_SEED: [u8; 8] = [0x11, 0x76, 0xde, 0x58, 0x11, 0x45, 0x9a, 0xb8];

#[inline(never)]
fn string_decode(input: &[u8]) -> String {
    let mut buf: Vec<u8> = vec![0u8; input.len()];

    for i in 0..input.len() {
        buf[i] = input[i] ^ S_SEED[i % S_SEED.len()];
    }

    String::from_utf8(buf).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn string_encode(str: &str) -> Vec<u8> {
        let input = str.as_bytes();
        let mut buf: Vec<u8> = vec![0u8; input.len()];

        for i in 0..input.len() {
            buf[i] = input[i] ^ S_SEED[i % S_SEED.len()];
        }

        return buf;
    }

    #[test]
    #[traced_test]
    fn test_strings() {
        tracing::error!("xxxx: {:?}", string_encode("abcdefghijklmnop"));

        assert_eq!(string_decode(&S_SS_PASSWORD).as_str(), "aaaaaaaa");

        #[cfg(feature = "trojan")]
        assert_eq!(string_decode(&S_TROJAN_PASSWORD).as_str(), "aaaaaaaa");

        #[cfg(feature = "vless")]
        assert_eq!(string_decode(&S_VLESS_TOKEN).as_str(), "abcdefghijklmnop");

        #[cfg(feature = "tuic")]
        assert_eq!(string_decode(&S_TUIC_TOKEN).as_str(), "aaaaaaaa");
    }
}
