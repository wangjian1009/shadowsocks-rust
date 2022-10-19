//! Server launchers

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use clap::{builder::PossibleValuesParser, Arg, ArgAction, ArgGroup, ArgMatches, Command, ValueHint};
use futures::future::{self, Either};
use tokio::{self, runtime::Builder};
use tracing::{error, info};

use shadowsocks_service::{
    acl::AccessControl,
    config::{read_variable_field_value, Config, ConfigType, ManagerConfig},
    run_server,
    shadowsocks::{
        canceler::Canceler,
        config::{ManagerAddr, Mode, ServerAddr, ServerConfig, ServerProtocol, ShadowsocksConfig},
        crypto::{available_ciphers, CipherKind},
        plugin::PluginConfig,
        transport::RateLimiter,
    },
};

#[cfg(feature = "rate-limit")]
use shadowsocks_service::shadowsocks::transport::BoundWidth;

#[cfg(feature = "transport")]
use shadowsocks_service::shadowsocks::config::TransportAcceptorConfig;

#[cfg(feature = "server-mock")]
use shadowsocks_service::shadowsocks::relay::socks5::Address;

#[cfg(feature = "trojan")]
use shadowsocks_service::shadowsocks::config::TrojanConfig;

#[cfg(feature = "vless")]
use shadowsocks_service::shadowsocks::{config::VlessConfig, vless::UUID};

#[cfg(feature = "tuic")]
use shadowsocks_service::shadowsocks::{
    config::TuicConfig,
    tuic::{server::RawConfig, CongestionController},
};

#[cfg(feature = "logging")]
use crate::logging;
use crate::{
    config::{Config as ServiceConfig, RuntimeMode},
    monitor, vparser,
};

/// Defines command line options
pub fn define_command_line_options(mut app: Command) -> Command {
    app = app
        .arg(
            Arg::new("CONFIG")
                .short('c')
                .long("config")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_hint(ValueHint::FilePath)
                .help("Shadowsocks configuration file (https://shadowsocks.org/guide/configs.html)"),
        )
        .arg(
            Arg::new("OUTBOUND_BIND_ADDR")
                .short('b')
                .long("outbound-bind-addr")
                .num_args(1)
                .action(ArgAction::Set)
                .alias("bind-addr")
                .value_parser(vparser::parse_ip_addr)
                .help("Bind address, outbound socket will bind this address"),
        )
        .arg(
            Arg::new("OUTBOUND_BIND_INTERFACE")
                .long("outbound-bind-interface")
                .num_args(1)
                .action(ArgAction::Set)
                .help("Set SO_BINDTODEVICE / IP_BOUND_IF / IP_UNICAST_IF option for outbound socket"),
        )
        .arg(
            Arg::new("SERVER_ADDR")
                .short('s')
                .long("server-addr")
                .num_args(1)
                .action(ArgAction::Set)
                .help("Server address"),
        )
        .arg(
            Arg::new("PROTOCOL_SS")
                .long("ss")
                .requires("SERVER_ADDR")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(&["PROTOCOL_TROJAN", "PROTOCOL_VLESS", "PROTOCOL_TUIC"])
                .help("Use shadowsocks protocol"),
        )
        .arg(
            Arg::new("SS_PASSWORD")
                .short('k')
                .long("password")
                .num_args(1)
                .action(ArgAction::Set)
                .requires("SERVER_ADDR")
                .help("Server's password"),
        )
        .arg(
            Arg::new("SS_ENCRYPT_METHOD")
                .short('m')
                .long("encrypt-method")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(PossibleValuesParser::new(available_ciphers()))
                .requires("SERVER_ADDR")
                .help("Server's encryption method"),
        )
        .arg(
            Arg::new("TIMEOUT")
                .long("timeout")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .requires("SERVER_ADDR")
                .help("Server's timeout seconds for TCP relay"),
        )
        .arg(
            Arg::new("REQUEST_RECV_TIMEOUT")
                .long("request-recv-timeout")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .requires("SERVER_ADDR")
                .help("request(upstream address) read timeout seconds for TCP relay"),
        )
        .arg(
            Arg::new("IDLE_TIMEOUT")
                .long("idle-timeout")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .requires("SERVER_ADDR")
                .help("idle timeout seconds for TCP relay"),
        )
        .group(
            ArgGroup::new("SERVER_CONFIG").arg("SERVER_ADDR")
        )
        .arg(
            Arg::new("UDP_ONLY")
                .short('u')
                .action(ArgAction::SetTrue)
                .conflicts_with("TCP_AND_UDP")
                .requires("SERVER_ADDR")
                .help("Server mode UDP_ONLY"),
        )
        .arg(
            Arg::new("TCP_AND_UDP")
                .short('U')
                .action(ArgAction::SetTrue)
                .requires("SERVER_ADDR")
                .help("Server mode TCP_AND_UDP"),
        )
        .arg(
            Arg::new("PLUGIN")
                .long("plugin")
                .num_args(1)
                .action(ArgAction::Set)
                .value_hint(ValueHint::CommandName)
                .requires("SERVER_ADDR")
                .help("SIP003 (https://shadowsocks.org/guide/sip003.html) plugin"),
        )
        .arg(
            Arg::new("PLUGIN_OPT")
                .long("plugin-opts")
                .num_args(1)
                .action(ArgAction::Set)
                .requires("PLUGIN")
                .help("Set SIP003 plugin options"),
        )
        .arg(Arg::new("MANAGER_ADDR").long("manager-addr").num_args(1).action(ArgAction::Set).value_parser(vparser::parse_manager_addr).alias("manager-address").help("ShadowSocks Manager (ssmgr) address, could be \"IP:Port\", \"Domain:Port\" or \"/path/to/unix.sock\""))
        .arg(Arg::new("ACL").long("acl").num_args(1).action(ArgAction::Set).value_hint(ValueHint::FilePath).help("Path to ACL (Access Control List)"))
        .arg(Arg::new("DNS").long("dns").num_args(1).action(ArgAction::Set).help("DNS nameservers, formatted like [(tcp|udp)://]host[:port][,host[:port]]..., or unix:///path/to/dns, or predefined keys like \"google\", \"cloudflare\""))
        .arg(Arg::new("TCP_NO_DELAY").long("tcp-no-delay").alias("no-delay").action(ArgAction::SetTrue).help("Set TCP_NODELAY option for sockets"))
        .arg(Arg::new("TCP_FAST_OPEN").long("tcp-fast-open").alias("fast-open").action(ArgAction::SetTrue).help("Enable TCP Fast Open (TFO)"))
        .arg(Arg::new("TCP_KEEP_ALIVE").long("tcp-keep-alive").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u64)).help("Set TCP keep alive timeout seconds"))
        .arg(Arg::new("UDP_TIMEOUT").long("udp-timeout").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u64)).help("Timeout seconds for UDP relay"))
        .arg(Arg::new("UDP_MAX_ASSOCIATIONS").long("udp-max-associations").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(usize)).help("Maximum associations to be kept simultaneously for UDP relay"))
        .arg(Arg::new("INBOUND_SEND_BUFFER_SIZE").long("inbound-send-buffer-size").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u32)).help("Set inbound sockets' SO_SNDBUF option"))
        .arg(Arg::new("INBOUND_RECV_BUFFER_SIZE").long("inbound-recv-buffer-size").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u32)).help("Set inbound sockets' SO_RCVBUF option"))
        .arg(Arg::new("OUTBOUND_SEND_BUFFER_SIZE").long("outbound-send-buffer-size").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u32)).help("Set outbound sockets' SO_SNDBUF option"))
        .arg(Arg::new("OUTBOUND_RECV_BUFFER_SIZE").long("outbound-recv-buffer-size").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u32)).help("Set outbound sockets' SO_RCVBUF option"))
        .arg(
            Arg::new("IPV6_FIRST")
                .short('6')
                .action(ArgAction::SetTrue)
                .help("Resolve hostname to IPv6 address first"),
        );

    #[cfg(feature = "vless")]
    {
        app = app
            .arg(
                Arg::new("PROTOCOL_VLESS")
                    .long("vless")
                    .requires("SERVER_ADDR")
                    .action(ArgAction::SetTrue)
                    .conflicts_with_all(&["PROTOCOL_TROJAN", "PROTOCOL_SS", "PROTOCOL_TUIC"])
                    .help("Use vless protocol"),
            )
            .arg(
                Arg::new("VLESS_USER")
                    .long("vless-user")
                    .requires("PROTOCOL_VLESS")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(UUID))
                    .help("Vless's users"),
            );
    }

    #[cfg(feature = "trojan")]
    {
        app = app
            .arg(
                Arg::new("PROTOCOL_TROJAN")
                    .long("trojan")
                    .requires("SERVER_ADDR")
                    .action(ArgAction::SetTrue)
                    .conflicts_with_all(&["PROTOCOL_VLESS", "PROTOCOL_SS", "PROTOCOL_TUIC"])
                    .help("Use trojan protocol"),
            )
            .arg(
                Arg::new("TROJAN_PASSWORD")
                    .long("trojan-password")
                    .action(ArgAction::Set)
                    .requires("PROTOCOL_TROJAN")
                    .help("Trojan server's password"),
            );
    }

    #[cfg(feature = "tuic")]
    {
        app = app
            .arg(
                Arg::new("PROTOCOL_TUIC")
                    .long("tuic")
                    .requires("SERVER_ADDR")
                    .action(ArgAction::SetTrue)
                    .conflicts_with_all(&["PROTOCOL_VLESS", "PROTOCOL_SS", "PROTOCOL_TROJAN"])
                    .help("Use tuic protocol"),
            )
            .arg(
                Arg::new("TUIC_CERT")
                    .long("tuic-cert")
                    .action(ArgAction::Set)
                    .requires("PROTOCOL_TUIC")
                    .help("tuic server's cert file path"),
            )
            .arg(
                Arg::new("TUIC_KEY")
                    .long("tuic-key")
                    .action(ArgAction::Set)
                    .requires("PROTOCOL_TUIC")
                    .help("tuic server's key file path"),
            )
            .arg(
                Arg::new("TUIC_TOKEN")
                    .long("tuic-token")
                    .action(ArgAction::Set)
                    .requires("PROTOCOL_TUIC")
                    .help("tuic server's user token"),
            )
            .arg(
                Arg::new("TUIC_ALPN")
                    .long("tuic-alpn")
                    .action(ArgAction::Set)
                    .requires("PROTOCOL_TUIC")
                    .help("tuic tls alpn config"),
            )
            .arg(
                Arg::new("TUIC_SHADOW_TCP")
                    .long("tuic-shadow-tcp")
                    .action(ArgAction::SetTrue)
                    .requires("PROTOCOL_TUIC")
                    .help("tuic server's start shadow tcp server"),
            )
            .arg(
                Arg::new("TUIC_CONGESTION_CONTROLLER")
                    .long("tuic-congestion-controller")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(CongestionController))
                    .requires("PROTOCOL_TUIC")
                    .help("tuic tls alpn config"),
            );
    }

    #[cfg(feature = "logging")]
    {
        app = app
            .arg(
                Arg::new("VERBOSE")
                    .short('v')
                    .action(ArgAction::Count)
                    .help("Set log level"),
            )
            .arg(
                Arg::new("LOG_WITHOUT_TIME")
                    .long("log-without-time")
                    .action(ArgAction::SetTrue)
                    .help("Log without datetime prefix"),
            );
    }

    #[cfg(feature = "logging-file")]
    {
        app = app.arg(
            Arg::new("LOG_TEMPLATE")
                .long("log-template")
                .action(ArgAction::Set)
                .help("log template file name"),
        );
    }

    #[cfg(feature = "logging-apm")]
    {
        app = app.arg(
            Arg::new("LOG_APM_URL")
                .long("log-apm-url")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(url::Url))
                .help("log apm server url"),
        );
    }

    #[cfg(feature = "logging-jaeger")]
    {
        app = app.arg(
            Arg::new("LOG_JAEGER_URL")
                .long("log-jaeger-url")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(url::Url))
                .help("log jaeger server url"),
        );
    }

    #[cfg(unix)]
    {
        app = app
            .arg(
                Arg::new("DAEMONIZE")
                    .short('d')
                    .long("daemonize")
                    .action(ArgAction::SetTrue)
                    .help("Daemonize"),
            )
            .arg(
                Arg::new("DAEMONIZE_PID_PATH")
                    .long("daemonize-pid")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(PathBuf))
                    .value_hint(ValueHint::FilePath)
                    .help("File path to store daemonized process's PID"),
            );
    }

    #[cfg(all(unix, not(target_os = "android")))]
    {
        app = app.arg(
            Arg::new("NOFILE")
                .short('n')
                .long("nofile")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .help("Set RLIMIT_NOFILE with both soft and hard limit"),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        app = app.arg(
            Arg::new("OUTBOUND_FWMARK")
                .long("outbound-fwmark")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u32))
                .help("Set SO_MARK option for outbound sockets"),
        );
    }

    #[cfg(target_os = "freebsd")]
    {
        app = app.arg(
            Arg::new("OUTBOUND_USER_COOKIE")
                .long("outbound-user-cookie")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u32))
                .help("Set SO_USER_COOKIE option for outbound sockets"),
        );
    }

    #[cfg(feature = "multi-threaded")]
    {
        app = app
            .arg(
                Arg::new("SINGLE_THREADED")
                    .long("single-threaded")
                    .action(ArgAction::SetTrue)
                    .help("Run the program all in one thread"),
            )
            .arg(
                Arg::new("WORKER_THREADS")
                    .long("worker-threads")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(usize))
                    .help("Sets the number of worker threads the `Runtime` will use"),
            );
    }

    #[cfg(feature = "server-maintain")]
    {
        app = app.arg(
            Arg::new("MAINTAIN_ADDR")
                .long("maintain-addr")
                .action(ArgAction::Set)
                .value_parser(vparser::parse_socket_addr)
                .help("Maintain server address"),
        );
    }

    #[cfg(feature = "transport")]
    {
        app = app.arg(
            Arg::new("TRANSPORT")
                .long("transport")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(TransportAcceptorConfig))
                .help("transport settings"),
        );
    }

    #[cfg(feature = "rate-limit")]
    {
        app = app.arg(
            Arg::new("CONN_LIMIT_RATE")
                .long("conn-limit-rate")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(BoundWidth))
                .help("connection speed rate limit per connection"),
        );
    }

    #[cfg(feature = "server-limit")]
    {
        app = app
            .arg(
                Arg::new("CONN_LIMIT_PER_IP")
                    .long("conn-limit-per-ip")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u32))
                    .help("connection limit per ip"),
            )
            .arg(
                Arg::new("CONN_LIMIT_CLOSE_DELAY")
                    .long("conn-limited-close-delay")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u32))
                    .help("limited connection close delay seconds"),
            );
    }

    #[cfg(feature = "server-mock")]
    {
        app = app.arg(
            Arg::new("MOCK_DNS")
                .long("mock-dns")
                .action(ArgAction::Set)
                .help("mock proxied dns connection to local"),
        );
    }

    #[cfg(unix)]
    {
        app = app.arg(
            Arg::new("USER")
                .long("user")
                .short('a')
                .num_args(1)
                .action(ArgAction::Set)
                .value_hint(ValueHint::Username)
                .help("Run as another user"),
        );
    }

    app
}

/// Program entrance `main`
pub fn main(matches: &ArgMatches) -> ExitCode {
    let (config, runtime, service_config) = {
        let config_path_opt = matches.get_one::<PathBuf>("CONFIG").cloned().or_else(|| {
            if !matches.contains_id("SERVER_CONFIG") {
                match crate::config::get_default_config_path() {
                    None => None,
                    Some(p) => {
                        println!("loading default config {:?}", p);
                        Some(p)
                    }
                }
            } else {
                None
            }
        });

        let mut service_config = match config_path_opt {
            Some(ref config_path) => match ServiceConfig::load_from_file(config_path) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("loading config {:?}, {}", config_path, err);
                    return crate::EXIT_CODE_LOAD_CONFIG_FAILURE.into();
                }
            },
            None => ServiceConfig::default(),
        };
        service_config.set_options(matches);

        let mut config = match config_path_opt {
            Some(cpath) => match Config::load_from_file(&cpath, ConfigType::Server) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("loading config {:?}, {}", cpath, err);
                    return crate::EXIT_CODE_LOAD_CONFIG_FAILURE.into();
                }
            },
            None => Config::new(ConfigType::Server),
        };

        if let Some(svr_addr) = matches.get_one::<String>("SERVER_ADDR") {
            let mut protocol = None;

            #[cfg(feature = "vless")]
            if protocol.is_none() && matches.get_flag("PROTOCOL_VLESS") {
                let mut vless_cfg = VlessConfig::new();

                match matches.get_one::<UUID>("VLESS_USER") {
                    Some(uuid) => {
                        vless_cfg.add_user(0, uuid.to_string().as_str(), None).unwrap();
                    }
                    None => {
                        eprintln!("missing `vless-user`");
                        return crate::EXIT_CODE_LOAD_CONFIG_FAILURE.into();
                    }
                };

                protocol = Some(ServerProtocol::Vless(vless_cfg));
            }

            #[cfg(feature = "trojan")]
            if protocol.is_none() && matches.get_flag("PROTOCOL_TROJAN") {
                let password = if let Some(pwd) = matches.get_one::<String>("TROJAN_PASSWORD") {
                    read_variable_field_value(pwd.as_str()).into()
                } else {
                    // NOTE: svr_addr should have been checked by crate::validator
                    match crate::password::read_server_password(svr_addr) {
                        Ok(pwd) => pwd,
                        Err(..) => panic!("`password` is required for server {}", svr_addr),
                    }
                };

                protocol = Some(ServerProtocol::Trojan(TrojanConfig::new(password)));
            }

            #[cfg(feature = "tuic")]
            if protocol.is_none() && matches.get_flag("PROTOCOL_TUIC") {
                let mut tuic_config = RawConfig::new(
                    matches.get_one::<String>("TUIC_CERT").cloned().unwrap(),
                    matches.get_one::<String>("TUIC_KEY").cloned().unwrap(),
                );

                if let Some(token_vec) = matches.get_many::<String>("TUIC_TOKEN") {
                    for token in token_vec.into_iter() {
                        tuic_config.token.push(token.to_string())
                    }
                }

                if let Some(alpn_vec) = matches.get_many::<String>("TUIC_ALPN") {
                    for alpn in alpn_vec.into_iter() {
                        tuic_config.alpn.push(alpn.to_string())
                    }
                }

                if let Some(congestion_controller) = matches
                    .try_get_one::<CongestionController>("TUIC_CONGESTION_CONTROLLER")
                    .unwrap()
                {
                    tuic_config.congestion_controller = congestion_controller.clone();
                }

                protocol = Some(ServerProtocol::Tuic(TuicConfig::Server((
                    tuic_config,
                    matches.get_flag("TUIC_SHADOW_TCP"),
                ))));
            }

            if protocol.is_none() && matches.get_flag("PROTOCOL_SS") {
                let method = matches
                    .get_one::<String>("SS_ENCRYPT_METHOD")
                    .map(|x| x.parse::<CipherKind>().expect("method"))
                    .expect("`method` is required");

                let password = match matches.get_one::<String>("SS_PASSWORD") {
                    Some(pwd) => read_variable_field_value(&pwd).into(),
                    None => {
                        // NOTE: svr_addr should have been checked by crate::validator
                        if method.is_none() {
                            // If method doesn't need a key (none, plain), then we can leave it empty
                            String::new()
                        } else {
                            match crate::password::read_server_password(svr_addr) {
                                Ok(pwd) => pwd,
                                Err(..) => panic!("`password` is required for server {}", svr_addr),
                            }
                        }
                    }
                };

                protocol = Some(ServerProtocol::SS(ShadowsocksConfig::new(password, method)));
            };

            if protocol.is_none() {
                eprintln!("No protocol specfic");
                return crate::EXIT_CODE_LOAD_CONFIG_FAILURE.into();
            }

            let svr_addr = svr_addr.parse::<ServerAddr>().expect("server-addr");

            let mut sc = ServerConfig::new(svr_addr, protocol.unwrap());

            // let method = matches.value_of_t_or_exit::<CipherKind>("ENCRYPT_METHOD");
            // let svr_addr = svr_addr.parse::<ServerAddr>().expect("server-addr");
            let timeout = matches.get_one::<u64>("TIMEOUT").map(|x| Duration::from_secs(*x));

            let request_recv_timeout = matches
                .get_one::<u64>("REQUEST_RECV_TIMEOUT")
                .cloned()
                .map(Duration::from_secs);

            let idle_timeout = matches.get_one::<u64>("IDLE_TIMEOUT").cloned().map(Duration::from_secs);
            if let Some(timeout) = timeout {
                sc.set_timeout(timeout);
            }

            if let Some(request_recv_timeout) = request_recv_timeout {
                sc.set_request_recv_timeout(request_recv_timeout);
            }

            if let Some(idle_timeout) = idle_timeout {
                sc.set_idle_timeout(idle_timeout);
            }

            if let Some(p) = matches.get_one::<String>("PLUGIN").cloned() {
                let plugin = PluginConfig {
                    plugin: p,
                    plugin_opts: matches.get_one::<String>("PLUGIN_OPT").cloned(),
                    plugin_args: Vec::new(),
                };

                sc.if_ss_mut(|c| c.set_plugin(plugin));
            }

            // For historical reason, servers that are created from command-line have to be tcp_only.
            sc.if_ss_mut(|c| c.set_mode(Mode::TcpOnly));

            if matches.get_flag("UDP_ONLY") {
                sc.if_ss_mut(|c| c.set_mode(Mode::UdpOnly));
            }

            if matches.get_flag("TCP_AND_UDP") {
                sc.if_ss_mut(|c| c.set_mode(Mode::TcpAndUdp));
            }

            config.server.push(sc);
        }

        if matches.get_flag("TCP_NO_DELAY") {
            config.no_delay = true;
        }

        if matches.get_flag("TCP_FAST_OPEN") {
            config.fast_open = true;
        }

        #[cfg(feature = "server-maintain")]
        if let Some(maintain_addr) = matches.get_one::<SocketAddr>("MAINTAIN_ADDR").cloned() {
            config.maintain_addr = Some(maintain_addr);
        }

        #[cfg(feature = "transport")]
        if let Some(acceptor_transport) = matches.get_one::<TransportAcceptorConfig>("TRANSPORT") {
            config
                .server
                .iter_mut()
                .for_each(|c| c.set_acceptor_transport(Some(acceptor_transport.clone())))
        }

        #[cfg(feature = "rate-limit")]
        if let Some(connection_speed_limit) = matches.get_one::<BoundWidth>("CONN_LIMIT_RATE") {
            let _ = RateLimiter::new(Some(connection_speed_limit.clone())).expect("speed limit rante error!");
            config.rate_limit = Some(connection_speed_limit.clone());
        }

        #[cfg(feature = "server-limit")]
        if let Some(limit_connection_per_ip) = matches.get_one::<u32>("CONN_LIMIT_PER_IP").cloned() {
            config.limit_connection_per_ip = Some(limit_connection_per_ip);
        }

        #[cfg(feature = "server-limit")]
        if let Some(limit_connection_close_delay) = matches
            .get_one::<u64>("CONN_LIMIT_CLOSE_DELAY")
            .cloned()
            .map(Duration::from_secs)
        {
            config.limit_connection_close_delay = Some(limit_connection_close_delay);
        }

        #[cfg(feature = "server-mock")]
        {
            if let Some(mock_dns_vec) = matches.get_many::<String>("MOCK_DNS") {
                for addr in mock_dns_vec
                    .map(|t| ServerAddr::from(Address::parse_with_dft_port(t, 53).expect("mock dns address")))
                {
                    config.mock_dns.push(addr);
                }
            }
        }

        if let Some(keep_alive) = matches
            .get_one::<u64>("TCP_KEEP_ALIVE")
            .cloned()
            .map(Duration::from_secs)
        {
            config.keep_alive = Some(keep_alive);
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(mark) = matches.get_one::<u32>("OUTBOUND_FWMARK") {
            config.outbound_fwmark = Some(*mark);
        }

        #[cfg(target_os = "freebsd")]
        if let Some(user_cookie) = matches.get_one::<u32>("OUTBOUND_USER_COOKIE") {
            config.outbound_user_cookie = Some(*user_cookie);
        }

        if let Some(iface) = matches.get_one::<String>("OUTBOUND_BIND_INTERFACE").cloned() {
            config.outbound_bind_interface = Some(iface);
        }

        if let Some(addr) = matches.get_one::<ManagerAddr>("MANAGER_ADDR").cloned() {
            if let Some(ref mut manager_config) = config.manager {
                manager_config.addr = addr;
            } else {
                config.manager = Some(ManagerConfig::new(addr));
            }
        }

        #[cfg(all(unix, not(target_os = "android")))]
        match matches.get_one::<u64>("NOFILE") {
            Some(nofile) => config.nofile = Some(*nofile),
            None => {
                if config.nofile.is_none() {
                    crate::sys::adjust_nofile();
                }
            }
        }

        if let Some(acl_file) = matches.get_one::<String>("ACL") {
            let acl = match AccessControl::load_from_file(acl_file) {
                Ok(acl) => acl,
                Err(err) => {
                    eprintln!("loading ACL \"{}\", {}", acl_file, err);
                    return crate::EXIT_CODE_LOAD_ACL_FAILURE.into();
                }
            };
            config.acl = Some(acl);
        }

        if let Some(dns) = matches.get_one::<String>("DNS") {
            config.set_dns_formatted(dns).expect("dns");
        }

        if matches.get_flag("IPV6_FIRST") {
            config.ipv6_first = true;
        }

        if let Some(udp_timeout) = matches.get_one::<u64>("UDP_TIMEOUT") {
            config.udp_timeout = Some(Duration::from_secs(*udp_timeout));
        }

        if let Some(udp_max_assoc) = matches.get_one::<usize>("UDP_MAX_ASSOCIATIONS") {
            config.udp_max_associations = Some(*udp_max_assoc);
        }

        if let Some(bs) = matches.get_one::<u32>("INBOUND_SEND_BUFFER_SIZE") {
            config.inbound_send_buffer_size = Some(*bs);
        }
        if let Some(bs) = matches.get_one::<u32>("INBOUND_RECV_BUFFER_SIZE") {
            config.inbound_recv_buffer_size = Some(*bs);
        }
        if let Some(bs) = matches.get_one::<u32>("OUTBOUND_SEND_BUFFER_SIZE") {
            config.outbound_send_buffer_size = Some(*bs);
        }
        if let Some(bs) = matches.get_one::<u32>("OUTBOUND_RECV_BUFFER_SIZE") {
            config.outbound_recv_buffer_size = Some(*bs);
        }

        if let Some(bind_addr) = matches.get_one::<IpAddr>("OUTBOUND_BIND_ADDR") {
            config.outbound_bind_addr = Some(*bind_addr);
        }

        // DONE READING options

        if config.server.is_empty() {
            eprintln!(
                "missing proxy servers, consider specifying it by \
                    --server-addr, --encrypt-method, --password command line option, \
                        or configuration file, check more details in https://shadowsocks.org/guide/configs.html"
            );
            return crate::EXIT_CODE_INSUFFICIENT_PARAMS.into();
        }

        if let Err(err) = config.check_integrity() {
            eprintln!("config integrity check failed, {}", err);
            return crate::EXIT_CODE_LOAD_CONFIG_FAILURE.into();
        }

        #[cfg(unix)]
        if matches.get_flag("DAEMONIZE") || matches.get_raw("DAEMONIZE_PID_PATH").is_some() {
            use crate::daemonize;
            daemonize::daemonize(matches.get_one::<PathBuf>("DAEMONIZE_PID_PATH"));
        }

        #[cfg(unix)]
        if let Some(uname) = matches.get_one::<String>("USER") {
            crate::sys::run_as_user(uname);
        }

        info!("shadowsocks server {} build {}", crate::VERSION, crate::BUILD_TIME);

        let mut worker_count = 1;
        let mut builder = match service_config.runtime.mode {
            RuntimeMode::SingleThread => Builder::new_current_thread(),
            #[cfg(feature = "multi-threaded")]
            RuntimeMode::MultiThread => {
                let mut builder = Builder::new_multi_thread();
                if let Some(worker_threads) = service_config.runtime.worker_count {
                    worker_count = worker_threads;
                    builder.worker_threads(worker_threads);
                } else {
                    worker_count = num_cpus::get();
                }

                builder
            }
        };
        config.worker_count = worker_count;

        let runtime = builder.enable_all().build().expect("create tokio Runtime");

        (config, runtime, service_config)
    };

    runtime.block_on(async move {
        #[cfg(feature = "logging")]
        let log_guard = logging::init_with_config("ssserver", &service_config.log);

        info!("{:?}", service_config);

        let app_cancel = Arc::new(Canceler::new());

        let abort_signal = monitor::create_signal_monitor(app_cancel.clone());
        let server = run_server(app_cancel.waiter(), config);

        tokio::pin!(abort_signal);
        tokio::pin!(server);

        let exit_code = match future::select(server, abort_signal).await {
            // Server future resolved without an error. This should never happen.
            Either::Left((Ok(..), ..)) => {
                info!("all server done");
                ExitCode::SUCCESS
            }
            // Server future resolved with error, which are listener errors in most cases
            Either::Left((Err(err), ..)) => {
                error!(error = ?err, "server exit with error");
                crate::EXIT_CODE_SERVER_ABORTED.into()
            }
            // The abort signal future resolved. Means we should just exit.
            Either::Right(_) => ExitCode::SUCCESS,
        };

        #[cfg(feature = "logging")]
        log_guard.close().await;

        exit_code
    })
}

#[cfg(test)]
mod test {
    use clap::Command;

    #[test]
    fn verify_server_command() {
        let mut app = Command::new("shadowsocks")
            .version(crate::VERSION)
            .about("A fast tunnel proxy that helps you bypass firewalls. (https://shadowsocks.org)");
        app = super::define_command_line_options(app);
        app.debug_assert();
    }
}
