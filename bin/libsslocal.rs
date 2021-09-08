use log::info;
use tokio::{self, runtime::Builder};
// use std::sync::mpsc;

mod local;

use shadowsocks_service::{
    config::{Config, ConfigType},
    run_local,
};

/// shadowsocks version
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[no_mangle]
fn lib_local_main(cpath: &str) -> i32 {
    info!("shadowsocks {}", VERSION);

    // let (tx, rx) = mpsc::channel();

    let config = match Config::load_from_file(cpath, ConfigType::Local) {
        Ok(mut cfg) => {
            for svr in cfg.server.iter_mut() {
                let password = local::decrypt_password(svr.password()).unwrap();
                svr.set_password(password.as_str());
            }
            cfg
        }
        Err(err) => {
            eprintln!("loading config \"{}\", {}", cpath, err);
            return -1;
        }
    };

    if config.local.is_empty() {
        eprintln!(
            "missing `local_address`, consider specifying it by \"local_address\" and \"local_port\" in configuration file"
        );
        return -1;
    }

    if config.server.is_empty() {
        eprintln!(
            "missing proxy servers, consider specifying it by configuration file, check more details in https://shadowsocks.org/en/config/quick-guide.html"
        );
        return -1;
    }

    if let Err(err) = config.check_integrity() {
        eprintln!("config integrity check failed, {}", err);
        return -1;
    }

    let mut builder = Builder::new_current_thread();
    let runtime = builder.enable_all().build().expect("create tokio Runtime");

    runtime.block_on(async move {
        let server = run_local(config);

        tokio::pin!(server);

        match server.await {
            // Server future resolved without an error. This should never happen.
            Ok(..) => {
                eprintln!("server exited unexpectly");
                // process::exit(common::EXIT_CODE_SERVER_EXIT_UNEXPECTLY);
            }
            // Server future resolved with error, which are listener errors in most cases
            Err(err) => {
                eprintln!("server aborted with {}", err);
                // process::exit(common::EXIT_CODE_SERVER_ABORTED);
            }
        }
    });

    0
}
