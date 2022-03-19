use log;
use spin::Mutex;
use std::{ffi::CStr, os::raw::c_char};
use tokio::{self, runtime::Builder, sync::mpsc};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "host-dns")] {
        use super::HostDns;
        use std::sync::Arc;
        use shadowsocks_service::config::DnsConfig;
    }
}

use shadowsocks_service::{
    acl::AccessControl,
    config::{Config, ConfigType},
    run_local,
    shadowsocks::config::ServerProtocol,
};

use futures::{
    stream::{FuturesUnordered, StreamExt},
    FutureExt,
};

#[derive(Debug)]
enum Command {
    Stop,
    #[cfg(feature = "host-dns")]
    UpdateHostDns(Vec<String>),
}

pub struct SSLocal {
    config: Config,
    ctrl_tx: Mutex<Option<Arc<mpsc::Sender<Command>>>>,
}

impl SSLocal {
    pub fn new(str_config: &str, acl_path: Option<&str>) -> SSLocal {
        log::info!("config {}", str_config);

        let mut config = Config::load_from_str(&str_config, ConfigType::Local).unwrap();
        log::info!("passed config {}", config);

        #[cfg(feature = "encrypt-password")]
        for svr in config.server.iter_mut() {
            match svr.protocol_mut() {
                ServerProtocol::SS(ss_cfg) => {
                    let password = crate::decrypt_password(ss_cfg.password()).unwrap();
                    ss_cfg.set_password(password.as_str());
                }
                #[cfg(feature = "trojan")]
                ServerProtocol::Trojan(cfg) => {
                    let password = crate::decrypt_password(cfg.password()).unwrap();
                    cfg.set_password(password.as_str());
                }
                #[cfg(feature = "vless")]
                ServerProtocol::Vless(..) => {}
            }
        }

        if config.local.is_empty() {
            log::error!(
                "missing `local_address`, consider specifying it by \"local_address\" and \"local_port\" in configuration file");
            panic!();
        }

        if config.server.is_empty() {
            log::error!(
            "missing proxy servers, consider specifying it by configuration file, check more details in https://shadowsocks.org/en/config/quick-guide.html"
        );
            panic!();
        }

        if let Err(err) = config.check_integrity() {
            log::error!("config integrity check failed, {}", err);
            panic!();
        }

        log::info!("loading config {}", config);

        if let Some(acl_path) = acl_path {
            let acl = match AccessControl::load_from_file(acl_path) {
                Ok(acl) => acl,
                Err(err) => {
                    log::error!("loading ACL \"{}\", {}", acl_path, err);
                    panic!();
                }
            };
            config.acl = Some(acl);

            log::error!("loading ACL \"{}\" success", acl_path);
        }

        SSLocal {
            config,
            ctrl_tx: Mutex::new(None),
        }
    }

    fn run(&mut self) {
        let mut builder = Builder::new_current_thread();
        let runtime = builder.enable_all().build().expect("create tokio Runtime");

        runtime.block_on(async move {
            let vfut = FuturesUnordered::new();

            let server = run_local(self.config.clone());
            vfut.push(
                async move {
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
                    };
                    ()
                }
                .boxed(),
            );

            #[cfg(feature = "host-dns")]
            let mut host_dns = None;

            #[cfg(feature = "host-dns")]
            if let DnsConfig::LocalDns(addr) = &self.config.dns {
                host_dns = Some(Arc::new(HostDns::new(addr.clone())));

                let host_dns = host_dns.clone();
                vfut.push(
                    async move {
                        match host_dns.as_ref().unwrap().run().await {
                            Ok(()) => log::info!("host dns stop success"),
                            Err(err) => log::error!("host dns stop with error {}", err),
                        }
                    }
                    .boxed(),
                );
            }

            let ctrl = self.run_ctrl(
                #[cfg(feature = "host-dns")]
                host_dns,
            );

            vfut.push(ctrl.boxed());

            let (_res, _) = vfut.into_future().await;

            log::info!("server stoped");
        });
    }

    fn stop(&self) {
        match self.ctrl_tx.lock().clone() {
            None => {
                log::error!("sslocal stop: not started");
            }
            Some(tx) => {
                tx.blocking_send(Command::Stop).unwrap();
            }
        }
    }

    #[cfg(feature = "host-dns")]
    fn update_host_dns(&self, servers: &Vec<&str>) {
        match self.ctrl_tx.lock().clone() {
            None => {
                log::error!("sslocal update host dns: not started");
            }
            Some(tx) => {
                tx.blocking_send(Command::UpdateHostDns(servers.iter().map(|s| s.to_string()).collect()))
                    .unwrap();
            }
        }
    }

    async fn run_ctrl(&mut self, #[cfg(feature = "host-dns")] host_dns: Option<Arc<HostDns>>) {
        let (tx, mut rx) = mpsc::channel(1);

        *self.ctrl_tx.lock() = Some(Arc::new(tx));

        while let Some(cmd) = rx.recv().await {
            match cmd {
                Command::Stop => {
                    break;
                }
                #[cfg(feature = "host-dns")]
                Command::UpdateHostDns(servers) => match host_dns.as_ref() {
                    None => {
                        log::info!("sslocal update host dns: no host dns")
                    }
                    Some(host_dns) => {
                        host_dns
                            .update_servers(servers.iter().map(|s| s.as_str()).collect())
                            .await
                    }
                },
            }
        }

        log::info!("server aborted ctrl stop");
    }
}

#[no_mangle]
pub extern "C" fn lib_local_new(c_config: *const c_char, c_acl_path: *const c_char) -> *mut SSLocal {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    oslog::OsLogger::new("com.example.test")
        .level_filter(log::LevelFilter::Debug)
        .category_level_filter("Settings", log::LevelFilter::Trace)
        .init()
        .unwrap();

    log::info!("shadowsocks local {} build {}", crate::VERSION, crate::BUILD_TIME);

    let str_config = unsafe { CStr::from_ptr(c_config).to_string_lossy().to_owned() };

    let mut acl_path: Option<String> = None;
    if !c_acl_path.is_null() {
        acl_path = unsafe { Some(CStr::from_ptr(c_acl_path).to_string_lossy().to_owned().into_owned()) };
    };

    Box::into_raw(Box::new(SSLocal::new(&str_config, acl_path.as_deref())))
}

#[no_mangle]
pub extern "C" fn lib_local_free(sslocal: *mut SSLocal) {
    unsafe {
        Box::from_raw(sslocal);
    }
}

#[no_mangle]
pub extern "C" fn lib_local_run(ptr: *mut SSLocal) {
    unsafe { (&mut *ptr).run() };
}

#[no_mangle]
pub extern "C" fn lib_local_stop(ptr: *mut SSLocal) {
    unsafe { (&mut *ptr).stop() };
}

#[no_mangle]
#[cfg(feature = "host-dns")]
pub extern "C" fn lib_local_update_host_dns(ptr: *mut SSLocal, c_dns_servers: *const c_char) {
    use std::ptr;

    unsafe {
        if c_dns_servers == ptr::null() {
            (&mut *ptr).update_host_dns(&vec![]);
        } else {
            let dns_servers = CStr::from_ptr(c_dns_servers).to_string_lossy().to_owned();
            let servers: Vec<&str> = dns_servers.split(";").collect();
            (&mut *ptr).update_host_dns(&servers);
        }
    };
}
