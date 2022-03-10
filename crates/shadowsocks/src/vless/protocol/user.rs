use super::Account;

#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub level: u32,
    pub email: Option<String>,
    pub account: Account,
}
