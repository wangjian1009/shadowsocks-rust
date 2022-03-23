use log;
use serde_json::{self, Map as JsonMap, Value};
use std::{
    ffi::CStr,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::raw::{c_char, c_ushort},
};
use tokio::net::UdpSocket;
use tokio::runtime::Builder;

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

#[no_mangle]
pub extern "C" fn lib_local_run(c_config: *const c_char, c_acl_path: *const c_char, control_port: c_ushort) {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    oslog::OsLogger::new("com.example.test")
        .level_filter(log::LevelFilter::Info)
        .init()
        .unwrap();

    log::info!("shadowsocks local {} build {}", crate::VERSION, crate::BUILD_TIME);

    let str_config = unsafe { CStr::from_ptr(c_config).to_string_lossy().to_owned() };

    let mut acl_path: Option<String> = None;
    if !c_acl_path.is_null() {
        acl_path = unsafe { Some(CStr::from_ptr(c_acl_path).to_string_lossy().to_owned().into_owned()) };
    };

    let config = load_config(&str_config, acl_path.as_deref());
    run(config, control_port);
}

fn load_config(str_config: &str, acl_path: Option<&str>) -> Config {
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

    config
}

fn run(config: Config, control_port: u16) {
    let mut builder = Builder::new_current_thread();
    let runtime = builder.enable_all().build().expect("create tokio Runtime");

    runtime.block_on(async move {
        let vfut = FuturesUnordered::new();

        let server = run_local(config.clone());
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
        if let DnsConfig::LocalDns(addr) = &config.dns {
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

        let ctrl = run_ctrl(
            control_port,
            #[cfg(feature = "host-dns")]
            host_dns,
        );

        vfut.push(ctrl.boxed());

        let (_res, _) = vfut.into_future().await;

        log::info!("server stoped");
    });
}

async fn run_ctrl(control_port: u16, #[cfg(feature = "host-dns")] host_dns: Option<Arc<HostDns>>) {
    match async move {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), control_port);
        let listener = UdpSocket::bind(addr).await?;
        log::info!("shadowsocks control listen on {}", addr);

        let mut buf = vec![0u8; 2048];
        loop {
            let n = listener.recv(&mut buf).await?;
            let cmd: JsonMap<String, Value> = match serde_json::from_slice(&buf[..n]) {
                Ok(v) => v,
                Err(err) => {
                    log::error!("control: cmd: {}, cmd parse error {}", "", err);
                    continue;
                }
            };

            let args = cmd.get("args");

            let cmd = match cmd.get("cmd") {
                None => {
                    log::error!("control: cmd: {:?}, no entry cmd", cmd);
                    continue;
                }
                Some(v) => match v {
                    Value::String(v) => v.as_str(),
                    _ => {
                        log::error!("control: cmd: {:?}, entry cmd not string", cmd);
                        continue;
                    }
                },
            };

            match cmd {
                "stop" => break,
                #[cfg(feature = "host-dns")]
                "update-host-dns" => {
                    if let Some(host_dns) = host_dns.as_ref() {
                        let mut servers = vec![];
                        if let Some(args) = args {
                            if !args.is_array() {
                                log::error!("control: {}: args not array", cmd);
                                continue;
                            }
                            for e in args.as_array().unwrap().iter() {
                                if !e.is_string() {
                                    log::error!("control: {}: ignore arg for not string", cmd);
                                    continue;
                                }
                                servers.push(e.as_str().unwrap());
                            }
                        }
                        host_dns.update_servers(servers).await;
                    }
                }
                _ => log::error!("control: not support cmd {}", cmd),
            }
        }

        log::info!("server aborted ctrl stop");
        io::Result::Ok(())
    }
    .await
    {
        Ok(()) => log::info!("server control stop success"),
        Err(err) => log::error!("server control stop with error {}", err),
    }
}
