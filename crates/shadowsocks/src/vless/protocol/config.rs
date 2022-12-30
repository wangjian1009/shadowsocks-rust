use std::io;

use super::{super::mux::ClientStrategy, Account, User};

#[derive(Clone, Debug, PartialEq)]
pub struct Fallback {
    pub alpn: String,
    pub path: String,
    pub type_: String,
    pub dest: String,
    pub xver: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub clients: Vec<User>,
    pub fallbacks: Option<Vec<Fallback>>,
    pub mux: Option<ClientStrategy>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            clients: Vec::new(),
            fallbacks: None,
            mux: None,
        }
    }

    pub fn add_user(&mut self, level: u32, uuid: &str, email: Option<String>) -> io::Result<()> {
        let user = User {
            level,
            email,
            account: Account::new(uuid.parse()?),
        };

        self.clients.push(user);

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}
