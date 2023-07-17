use super::{common::UUID, protocol::User};
use std::{collections::HashMap, io, sync::Arc};

pub struct Validator {
    email: HashMap<String, Arc<User>>,
    users: HashMap<UUID, Arc<User>>,
}

impl Validator {
    pub fn new() -> Self {
        Self {
            email: HashMap::new(),
            users: HashMap::new(),
        }
    }

    // Add a VLESS user, Email must be empty or unique.
    #[inline]
    pub fn add(&mut self, user: User) -> io::Result<()> {
        let user = Arc::new(user);
        if let Some(email) = user.email.as_ref() {
            if let Some(..) = self.email.insert(email.to_lowercase(), user.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("User {email} already exists."),
                ));
            }
        }

        self.users.insert(user.account.id.clone(), user);
        Ok(())
    }

    // Del a VLESS user with a non-empty Email.
    #[inline]
    pub fn del(&mut self, e: &str) -> io::Result<Arc<User>> {
        let le = e.to_lowercase();
        match self.email.remove(&le) {
            None => Err(io::Error::new(io::ErrorKind::Other, format!("User {e} not found."))),
            Some(user) => {
                self.users.remove(&user.account.id);
                Ok(user)
            }
        }
    }

    // Get a VLESS user with UUID, nil if user doesn't exist.
    #[inline]
    pub fn get(&self, id: &UUID) -> Option<Arc<User>> {
        self.users.get(id).cloned()
    }
}
