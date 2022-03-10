use std::io;

use super::{Account, User};

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
    pub decryption: Option<String>,
    pub fallbacks: Option<Vec<Fallback>>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            clients: Vec::new(),
            decryption: None,
            fallbacks: None,
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
