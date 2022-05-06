use std::time::Duration;

use super::super::{HeaderConfig, HeaderPolicy, Security, SecurityConfig};

/// Kcp Delay Config
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KcpNoDelayConfig {
    /// Enable nodelay
    pub nodelay: bool,
    /// Internal update interval (ms)
    pub interval: i32,
    /// ACK number to enable fast resend
    pub resend: i32,
    /// Disable congetion control
    pub nc: bool,
}

impl Default for KcpNoDelayConfig {
    fn default() -> KcpNoDelayConfig {
        KcpNoDelayConfig {
            nodelay: false,
            interval: 100,
            resend: 0,
            nc: false,
        }
    }
}

impl KcpNoDelayConfig {
    /// Get a fastest configuration
    ///
    /// 1. Enable NoDelay
    /// 2. Set ticking interval to be 10ms
    /// 3. Set fast resend to be 2
    /// 4. Disable congestion control
    pub fn fastest() -> KcpNoDelayConfig {
        KcpNoDelayConfig {
            nodelay: true,
            interval: 10,
            resend: 2,
            nc: true,
        }
    }

    /// Get a normal configuration
    ///
    /// 1. Disable NoDelay
    /// 2. Set ticking interval to be 40ms
    /// 3. Disable fast resend
    /// 4. Enable congestion control
    pub fn normal() -> KcpNoDelayConfig {
        KcpNoDelayConfig {
            nodelay: false,
            interval: 40,
            resend: 0,
            nc: false,
        }
    }
}

/// Kcp Config
#[derive(Debug, Clone, PartialEq)]
pub struct KcpConfig {
    /// Max Transmission Unit
    pub mtu: usize,
    /// nodelay
    pub nodelay: KcpNoDelayConfig,
    /// Send window size
    pub wnd_size: (u16, u16),
    /// Session expire duration, default is 90 seconds
    pub session_expire: Duration,
    /// Flush KCP state immediately after write
    pub flush_write: bool,
    /// Flush ACKs immediately after input
    pub flush_acks_input: bool,
    /// Stream mode
    pub stream: bool,
    // KCP 进行伪装, utp、srtp、wechat-video、dtls、wireguard 或者 none
    pub header_config: Option<HeaderConfig>,
    // 数据加密（验证）配置 simple,aes-gcm
    pub security_config: Option<SecurityConfig>,
}

impl Default for KcpConfig {
    fn default() -> KcpConfig {
        KcpConfig {
            mtu: 1400,
            nodelay: KcpNoDelayConfig::normal(),
            wnd_size: (256, 256),
            session_expire: Duration::from_secs(90),
            flush_write: false,
            flush_acks_input: false,
            stream: true,
            header_config: None,
            security_config: None,
        }
    }
}

impl KcpConfig {
    pub fn create_header(&self) -> Option<HeaderPolicy> {
        match self.header_config.as_ref() {
            None => None,
            Some(head_config) => Some(head_config.create_policy()),
        }
    }

    pub fn create_security(&self) -> Option<Security> {
        match self.security_config.as_ref() {
            None => None,
            Some(security_config) => Some(security_config.create_security()),
        }
    }
}
