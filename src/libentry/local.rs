use serde_json::{self, Map as JsonMap, Value};
use std::{
    ffi::CStr,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::raw::{c_char, c_ushort},
    sync::Arc,
};
use tokio::net::UdpSocket;
use tokio::runtime::Builder;
use tokio::time::{sleep, Duration};
use tracing::{error, info, info_span, Instrument};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "host-dns")] {
        use super::HostDns;
        use shadowsocks_service::config::DnsConfig;
    }
}

use shadowsocks_service::{
    acl::AccessControl,
    config::{Config, ConfigType},
    run_local,
    shadowsocks::canceler::Canceler,
};

#[cfg(feature = "local-flow-stat")]
use shadowsocks_service::config::LocalFlowStatAddress;

use futures::{
    stream::{FuturesUnordered, StreamExt},
    FutureExt,
};

#[no_mangle]
pub extern "C" fn lib_local_run(
    c_config: *const c_char,
    c_log_level: c_char,
    c_acl_path: *const c_char,
    #[cfg(feature = "local-flow-stat")] c_stat_path: *const c_char,
    control_port: c_ushort,
    #[cfg(target_os = "android")] c_vpn_protect_path: *const c_char,
) {
    let str_config = unsafe { CStr::from_ptr(c_config).to_string_lossy().to_owned() };

    let acl_path = if !c_acl_path.is_null() {
        unsafe { Some(CStr::from_ptr(c_acl_path).to_string_lossy().to_owned().into_owned()) }
    } else {
        None
    };

    #[cfg(feature = "local-flow-stat")]
    let stat_path = if !c_stat_path.is_null() {
        unsafe { Some(CStr::from_ptr(c_stat_path).to_string_lossy().to_owned().into_owned()) }
    } else {
        None
    };

    #[cfg(target_os = "android")]
    let vpn_protect_path = if !c_vpn_protect_path.is_null() {
        unsafe {
            Some(
                CStr::from_ptr(c_vpn_protect_path)
                    .to_string_lossy()
                    .to_owned()
                    .into_owned(),
            )
        }
    } else {
        None
    };

    let mut builder = Builder::new_current_thread();
    let runtime = builder.enable_all().build().expect("create tokio Runtime");

    runtime.block_on(async move {
        let config = load_config(
            &str_config,
            acl_path.as_deref(),
            control_port,
            #[cfg(feature = "local-flow-stat")]
            stat_path.as_deref(),
            #[cfg(target_os = "android")]
            vpn_protect_path.as_deref(),
        );

        #[cfg(feature = "logging")]
        let log_guard = {
            let mut log_config = crate::config::LogConfig::default();
            log_config.level = c_log_level as u32;
            crate::logging::init_with_config("sslocal", &log_config)
        };

        run(config, control_port).await;

        #[cfg(feature = "logging")]
        log_guard.close().await;
    });
}

fn load_config(
    str_config: &str,
    acl_path: Option<&str>,
    control_port: u16,
    #[cfg(feature = "local-flow-stat")] stat_path: Option<&str>,
    #[cfg(target_os = "android")] vpn_protect_path: Option<&str>,
) -> Config {
    let mut config = match Config::load_from_str(str_config, ConfigType::Local) {
        Ok(c) => c,
        Err(e) => {
            panic!("load_config fail: {}", e);
        }
    };

    if config.local.is_empty() {
        panic!(
            "missing `local_address`, consider specifying it by \"local_address\" and \"local_port\" in configuration file");
    }

    if config.server.is_empty() {
        panic!(
            "missing proxy servers, consider specifying it by configuration file, check more details in https://shadowsocks.org/en/config/quick-guide.html"
        );
    }

    if let Err(err) = config.check_integrity() {
        panic!("config integrity check failed, {}", err);
    }

    #[cfg(target_os = "android")]
    if let Some(vpn_protect_path) = vpn_protect_path {
        // A socket `protect_path` in CWD
        // Same as shadowsocks-libev's android.c
        config.outbound_vpn_protect_path = Some(From::from(vpn_protect_path));
    }

    #[cfg(feature = "local-maintain")]
    if control_port > 0 {
        config.maintain_addr = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), control_port));
    }

    #[cfg(feature = "local-flow-stat")]
    if let Some(stat_path) = stat_path {
        config.local_stat_addr = Some(LocalFlowStatAddress::UnixStreamPath(From::from(stat_path)));
    }

    if let Some(acl_path) = acl_path {
        let acl = match AccessControl::load_from_file(acl_path) {
            Ok(acl) => acl,
            Err(err) => {
                panic!("loading ACL \"{}\", {}", acl_path, err);
            }
        };
        config.acl = Some(acl);
    }

    config
}

async fn run(config: Config, control_port: u16) {
    let vfut = FuturesUnordered::new();
    let canceler = Arc::new(Canceler::new());

    info!("shadowsocks local {} build {}", crate::VERSION, crate::BUILD_TIME);
    info!("{:?}", config);

    let server = run_local(config.clone(), canceler.waiter());
    vfut.push(
        async move {
            match server.await {
                // Server future resolved without an error. This should never happen.
                Ok(..) => {
                    info!("server exited unexpectly");
                    // process::exit(common::EXIT_CODE_SERVER_EXIT_UNEXPECTLY);
                }
                // Server future resolved with error, which are listener errors in most cases
                Err(err) => {
                    error!("server aborted with {}", err);
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
        let waiter = canceler.waiter();

        let host_dns = host_dns.clone();
        vfut.push(
            async move {
                tokio::select! {
                    r = host_dns.as_ref().unwrap().run() => {
                        match r {
                            Ok(()) => info!("stop success"),
                            Err(err) => error!(error = ?err, "stop with error"),
                        }
                    }
                    _ = waiter.wait() => {
                        info!("canceled");
                    }
                }
            }
            .instrument(info_span!("host-dns"))
            .boxed(),
        );
    }

    tokio::select! {
        _r = vfut.into_future() => {
            info!("all server stop success");
        }
        _ = run_ctrl(control_port, canceler, #[cfg(feature = "host-dns")] host_dns)
            .instrument(info_span!("local-ctrl")) => {
            info!("break runing for ctrl exited");
        }
    }
}

async fn run_ctrl(
    control_port: u16,
    canceler: Arc<Canceler>,
    #[cfg(feature = "host-dns")] host_dns: Option<Arc<HostDns>>,
) {
    match async move {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), control_port);
        let listener = UdpSocket::bind(addr).await?;
        info!("shadowsocks control listen on {}", addr);

        let mut buf = vec![0u8; 2048];
        loop {
            let n = listener.recv(&mut buf).await?;
            let cmd: JsonMap<String, Value> = match serde_json::from_slice(&buf[..n]) {
                Ok(v) => v,
                Err(err) => {
                    error!("control: cmd: {}, cmd parse error {}", "", err);
                    continue;
                }
            };

            #[allow(unused_variables)]
            let args = cmd.get("args");

            let cmd = match cmd.get("cmd") {
                None => {
                    error!("control: cmd: {:?}, no entry cmd", cmd);
                    continue;
                }
                Some(v) => match v {
                    Value::String(v) => v.as_str(),
                    _ => {
                        error!("control: cmd: {:?}, entry cmd not string", cmd);
                        continue;
                    }
                },
            };

            match cmd {
                "stop" => {
                    info!("received cmd stop, soft exiting");
                    canceler.cancel();
                    sleep(Duration::from_secs(1)).await;
                    info!("received cmd stop, force exiting");
                    break;
                }
                #[cfg(feature = "host-dns")]
                "update-host-dns" => {
                    if let Some(host_dns) = host_dns.as_ref() {
                        let mut servers = vec![];
                        if let Some(args) = args {
                            if !args.is_array() {
                                error!("control: {}: args not array", cmd);
                                continue;
                            }
                            for e in args.as_array().unwrap().iter() {
                                if !e.is_string() {
                                    error!("control: {}: ignore arg for not string", cmd);
                                    continue;
                                }
                                servers.push(e.as_str().unwrap());
                            }
                        }
                        host_dns.update_servers(servers).await;
                    }
                }
                #[cfg(feature = "rate-limit")]
                "update-rate-limit" => match on_update_speed_limit(control_port, args).await {
                    Ok(()) => {}
                    Err(e) => {
                        error!("control: {}: error {}", cmd, e);
                    }
                },
                _ => error!("control: not support cmd {}", cmd),
            }
        }

        info!("server aborted ctrl stop");
        io::Result::Ok(())
    }
    .await
    {
        Ok(()) => info!("server control stop success"),
        Err(err) => error!("server control stop with error {}", err),
    }
}

#[cfg(feature = "rate-limit")]
async fn on_update_speed_limit(maintain_port: u16, args: Option<&Value>) -> io::Result<()> {
    use hyper::{Body, Client, Method, Request};

    let bps = match args {
        Some(args) => match args.as_u64() {
            Some(s) => Some(s),
            None => {
                return Err(io::Error::new(io::ErrorKind::Other, "arg not number"));
            }
        },
        None => None,
    };

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://127.0.0.1:{}/speed-limit", maintain_port))
        .body(match bps {
            Some(bps) => Body::from(format!("{}", bps)),
            None => Body::empty(),
        })
        .expect("request builder");

    let client = Client::new();

    let rsp = client
        .request(req)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;

    info!("control: update speed limit: rsp={:?}", rsp);
    Ok(())
}
