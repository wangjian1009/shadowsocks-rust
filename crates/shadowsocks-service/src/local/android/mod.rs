use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "local-signed-info")] {
        mod env;
        mod validate;
        mod signed_data;
        mod sha1;

        pub use validate::{ValidateResult, validate_sign, ValidateError};
    }
}
