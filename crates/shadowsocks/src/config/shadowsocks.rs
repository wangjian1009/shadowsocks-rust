use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct ShadowsocksConfig {
    /// Encryption password (key)
    password: String,
    /// Encryption type (method)
    method: CipherKind,
    /// Encryption key
    enc_key: Box<[u8]>,

    /// Extensible Identity Headers (AEAD-2022)
    ///
    /// For client, assemble EIH headers
    identity_keys: Arc<Vec<Bytes>>,

    /// Extensible Identity Headers (AEAD-2022)
    ///
    /// For server, support multi-users with EIH
    user_manager: Option<Arc<ServerUserManager>>,

    /// Plugin config
    plugin: Option<PluginConfig>,
    /// Plugin address
    plugin_addr: Option<ServerAddr>,

    /// ID (SIP008) is a random generated UUID
    id: Option<String>,
}

impl ShadowsocksConfig {
    /// Create a new `ShadowsocksConfig`
    pub fn new<P>(password: P, method: CipherKind) -> Self
    where
        P: Into<String>,
    {
        let (password, enc_key, identity_keys) = password_to_keys(method, password);

        ShadowsocksConfig {
            password,
            method,
            enc_key,
            identity_keys: Arc::new(identity_keys),
            user_manager: None,
            plugin: None,
            plugin_addr: None,
            id: None,
        }
    }

    /// Set plugin
    pub fn set_plugin(&mut self, p: PluginConfig) {
        self.plugin = Some(p);
    }

    /// Get encryption key
    pub fn key(&self) -> &[u8] {
        self.enc_key.as_ref()
    }

    /// Set password
    pub fn set_password(&mut self, password: &str) {
        self.password = password.to_string();

        let mut enc_key = vec![0u8; self.method.key_len()].into_boxed_slice();
        openssl_bytes_to_key(self.password.as_bytes(), &mut enc_key);
        self.enc_key = enc_key;
    }

    /// Get password
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    /// Get identity keys (Client)
    pub fn identity_keys(&self) -> &[Bytes] {
        &self.identity_keys
    }

    /// Clone identity keys (Client)
    pub fn clone_identity_keys(&self) -> Arc<Vec<Bytes>> {
        self.identity_keys.clone()
    }

    /// Set user manager, enable Server's multi-user support with EIH
    pub fn set_user_manager(&mut self, user_manager: ServerUserManager) {
        self.user_manager = Some(Arc::new(user_manager));
    }

    /// Get user manager (Server)
    pub fn user_manager(&self) -> Option<&ServerUserManager> {
        self.user_manager.as_deref()
    }

    /// Clone user manager (Server)
    pub fn clone_user_manager(&self) -> Option<Arc<ServerUserManager>> {
        self.user_manager.clone()
    }

    /// Get method
    pub fn method(&self) -> CipherKind {
        self.method
    }

    /// Set encryption method
    pub fn set_method<P>(&mut self, method: CipherKind, password: P)
    where
        P: Into<String>,
    {
        self.method = method;
        self.password = password.into();

        let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
        make_derived_key(method, &self.password, &mut enc_key);

        self.enc_key = enc_key;
    }

    /// Get plugin
    pub fn plugin(&self) -> Option<&PluginConfig> {
        self.plugin.as_ref()
    }

    /// Set plugin address
    pub fn set_plugin_addr(&mut self, a: ServerAddr) {
        self.plugin_addr = Some(a);
    }

    /// Get plugin address
    pub fn plugin_addr(&self) -> Option<&ServerAddr> {
        self.plugin_addr.as_ref()
    }

    /// Get server's ID (SIP008)
    pub fn id(&self) -> Option<&str> {
        self.id.as_ref().map(AsRef::as_ref)
    }

    /// Set server's ID (SIP008)
    pub fn set_id<S>(&mut self, id: S)
    where
        S: Into<String>,
    {
        self.id = Some(id.into())
    }
}
