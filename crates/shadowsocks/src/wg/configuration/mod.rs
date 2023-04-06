mod config;
mod error;
pub mod uapi;

use super::platform::Endpoint;
use super::platform::{tun, udp};
use super::wireguard::WireGuard;

pub use error::ConfigError;

pub use config::Configuration;
pub use config::WireGuardConfig;

pub async fn set_configuration(config: &impl Configuration, content: &str) -> Result<(), ConfigError> {
    tracing::debug!("UAPI, Set operation");
    let mut parser = uapi::LineParser::new(config);
    for ln in content.lines() {
        if ln == "" {
            break;
        }
        let (k, v) = keypair(ln)?;
        parser.parse_line(k, v).await?;
    }

    parser.parse_line("", "").await
}

// split into (key, value) pair
fn keypair(ln: &str) -> Result<(&str, &str), ConfigError> {
    let mut split = ln.splitn(2, '=');
    match (split.next(), split.next()) {
        (Some(key), Some(value)) => Ok((key, value)),
        _ => Err(ConfigError::LineTooLong),
    }
}
