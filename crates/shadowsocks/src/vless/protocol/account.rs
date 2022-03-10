use super::super::common::UUID;

#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    // ID of the account, in the form of a UUID, e.g., "66ad4540-b58c-4ad2-9926-ea63445a9b57".
    pub id: UUID,
    // Flow settings.
    pub flow: Option<String>,
    // Encryption settings. Only applies to client side, and only accepts "none" for now.
    pub encryption: Option<String>,
}

impl Account {
    pub fn new(id: UUID) -> Self {
        Self {
            id,
            flow: None,
            encryption: None,
        }
    }
}
