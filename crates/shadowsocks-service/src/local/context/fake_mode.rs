use super::*;

#[derive(Debug, Clone)]
pub enum FakeMode {
    None,
    Bypass,
    ParamError,
}

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
                new_cfg.set_password("aaaaaaaa");
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
                new_cfg.set_password("aaaaaaaa");
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
                    client.account.id = shadowsocks::vless::UUID::parse_bytes("abcdefghijklmnop".as_bytes()).unwrap();
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
                    new_cfg.token = "aaaaaaaa".to_owned();
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
        self.fake_mode.lock().clone()
    }

    pub fn set_fake_mode(&self, mode: FakeMode) {
        if {
            let mut old_mode = self.fake_mode.lock();
            let need_close_connections = if let FakeMode::None = *old_mode { true } else { false };
            *old_mode = mode;
            need_close_connections
        } {
            self.close_connections()
        }
    }
}
