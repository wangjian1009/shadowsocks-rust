use sha2::Digest;

use crate::config::ServerAddr;

#[derive(Clone, Debug, PartialEq)]
pub struct Password(Vec<u8>);

impl Password {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn make_password(h: &str) -> Password {
    let mut hasher = sha2::Sha512::new();
    hasher.update(h.as_bytes());
    let res = hasher.finalize();
    let mut res_vec = Vec::new();
    res_vec.extend_from_slice(res.as_slice());
    Password(res_vec)
}

#[derive(Clone, Debug, PartialEq)]
pub struct RestlsConfig {
    /// Server Name Indication (sni), or Hostname.
    pub server_hostname: ServerAddr,

    /// the password to authenticate connections
    pub password: Password,
}

impl RestlsConfig {
    pub fn new(server_hostname: ServerAddr, password: &str) -> Self {
        Self {
            server_hostname,
            password: make_password(password),
        }
    }
}
