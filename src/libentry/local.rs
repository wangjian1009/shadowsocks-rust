use std::{ffi::CStr, ops::Deref, os::raw::c_char, sync::Arc};
use tokio::{self, runtime::Builder, sync::mpsc};

use super::HostDns;

use shadowsocks_service::{
    acl::AccessControl,
    config::{Config, ConfigType, DnsConfig},
    run_local,
};

#[derive(Debug)]
enum Command {
    Stop,
    #[cfg(feature = "host-dns")]
    UpdateHostDns(Vec<String>),
}

pub struct SSLocal {
    config: Config,
    ctrl_tx: Option<mpsc::Sender<Command>>,
}

impl SSLocal {
    pub fn new(str_config: &str, acl_path: Option<&str>) -> SSLocal {
        log::info!("config {}", str_config);

        let mut config = Config::load_from_str(&str_config, ConfigType::Local).unwrap();

        #[cfg(feature = "encrypt-password")]
        for svr in config.server.iter_mut() {
            let password = crate::decrypt_password(svr.password()).unwrap();
            log::info!("password {} ==> {}", svr.password(), password);
            svr.set_password(password.as_str());
            log::info!("server {} password {}", svr.addr(), svr.password());
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

        SSLocal { config, ctrl_tx: None }
    }

    #[cfg(feature = "host-dns")]
    fn create_host_dns(&mut self) -> Option<Arc<HostDns>> {
        match &self.config.dns {
            DnsConfig::LocalDns(ref local_addr) => Some(Arc::new(HostDns::new(local_addr.clone()))),
            _ => None,
        }
    }

    fn run(&mut self) {
        let mut builder = Builder::new_current_thread();
        let runtime = builder.enable_all().build().expect("create tokio Runtime");

        runtime.block_on(async move {
            let host_dns = self.create_host_dns();
            let ctrl = self.start_ctrl(host_dns.clone());

            let server = run_local(self.config.clone());

            let dns = tokio::spawn(async move {
                #[cfg(feature = "host-dns")]
                if let Some(ref host_dns) = host_dns {
                    match host_dns.deref().run().await {
                        Ok(()) => log::info!("host dns stop success"),
                        Err(err) => log::error!("host dns stop with error {}", err),
                    }
                };
            });

            tokio::pin!(ctrl);

            tokio::pin!(server, dns);

            tokio::select! {
                val = server => {
                    match val {
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
                }
                _ = ctrl => {
                    log::error!("server aborted ctrl stop");
                }
                _ = dns => {
                    log::error!("server aborted host dns stop");
                }
            }
        });
    }

    fn stop(&self) {
        match &self.ctrl_tx {
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
        match &self.ctrl_tx {
            None => {
                log::error!("sslocal update host dns: not started");
            }
            Some(tx) => {
                tx.blocking_send(Command::UpdateHostDns(servers.iter().map(|s| s.to_string()).collect()))
                    .unwrap();
            }
        }
    }

    fn start_ctrl(&mut self, host_dns: Option<Arc<HostDns>>) -> tokio::task::JoinHandle<()> {
        let (tx, mut rx) = mpsc::channel(1);

        self.ctrl_tx = Some(tx);

        tokio::spawn(async move {
            let host_dns: Option<&HostDns> = match &host_dns {
                None => None,
                Some(ref host_dns) => Some(host_dns.deref()),
            };

            while let Some(cmd) = rx.recv().await {
                match cmd {
                    Command::Stop => {
                        break;
                    }
                    #[cfg(feature = "host-dns")]
                    Command::UpdateHostDns(servers) => match &host_dns {
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
        })
    }
}

#[no_mangle]
pub extern "C" fn lib_local_new(c_config: *const c_char, c_acl_path: *const c_char) -> *mut SSLocal {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    super::apple::logger::init().unwrap();

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
