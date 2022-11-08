use std::os::raw::c_int;

#[cfg(feature = "logging")]
use crate::{config::LogConfig, logging};

#[cfg(feature = "logging")]
static mut LOG_GUARD: Option<logging::Guard> = None;

#[no_mangle]
pub extern "C" fn lib_log_init(level: c_int) {
    #[cfg(feature = "logging")]
    unsafe {
        LOG_GUARD = {
            let mut log_config = LogConfig::default();
            log_config.level = level as u32;
            log_config.format.without_time = true;
            Some(logging::init_with_config("sslocal", &log_config))
        };
    }
}

#[no_mangle]
pub extern "C" fn lib_log_teardown() {
    #[cfg(feature = "logging")]
    unsafe {
        LOG_GUARD = None;
    }
}
