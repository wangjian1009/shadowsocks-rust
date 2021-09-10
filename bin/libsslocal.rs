use log;
use std::{ffi::CStr, os::raw::c_char};
use tokio::{self, runtime::Builder};
// use std::sync::mpsc;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;

mod local;

use shadowsocks_service::{
    config::{Config, ConfigType},
    run_local,
};

/// shadowsocks version
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[no_mangle]
fn lib_local_main(c_config: *const c_char) -> i32 {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    apple::logger::init().unwrap();

    log::info!("shadowsocks {}", VERSION);

    let str_config = unsafe { CStr::from_ptr(c_config).to_string_lossy().to_owned() };

    log::info!("config {}", str_config);

    // let (tx, rx) = mpsc::channel();

    let config = match Config::load_from_str(&str_config, ConfigType::Local) {
        Ok(mut cfg) => {
            for svr in cfg.server.iter_mut() {
                let password = local::decrypt_password(svr.password()).unwrap();
                log::info!("password {} ==> {}", svr.password(), password);
                svr.set_password(password.as_str());
                log::info!("server {} password {}", svr.addr(), svr.password());
            }
            cfg
        }
        Err(err) => {
            log::error!("loading config {}, \"{}\"", err, &str_config);
            return -1;
        }
    };

    if config.local.is_empty() {
        log::error!(
            "missing `local_address`, consider specifying it by \"local_address\" and \"local_port\" in configuration file"
        );
        return -1;
    }

    if config.server.is_empty() {
        log::error!(
            "missing proxy servers, consider specifying it by configuration file, check more details in https://shadowsocks.org/en/config/quick-guide.html"
        );
        return -1;
    }

    if let Err(err) = config.check_integrity() {
        log::error!("config integrity check failed, {}", err);
        return -1;
    }

    log::info!("loading config {}", config);

    let mut builder = Builder::new_current_thread();
    let runtime = builder.enable_all().build().expect("create tokio Runtime");

    runtime.block_on(async move {
        let server = run_local(config);

        tokio::pin!(server);

        match server.await {
            // Server future resolved without an error. This should never happen.
            Ok(..) => {
                log::info!("server exited unexpectly");
                // process::exit(common::EXIT_CODE_SERVER_EXIT_UNEXPECTLY);
            }
            // Server future resolved with error, which are listener errors in most cases
            Err(err) => {
                log::error!("server aborted with {}", err);
                // process::exit(common::EXIT_CODE_SERVER_ABORTED);
            }
        }
    });

    0
}
