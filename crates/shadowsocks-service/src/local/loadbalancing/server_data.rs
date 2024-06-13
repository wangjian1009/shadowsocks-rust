//! Identifier of server

use std::{
    fmt::{self, Debug},
    io,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use shadowsocks::{net::ConnectOpts, ServerConfig};
use tokio::sync::Mutex;

use crate::{config::ServerInstanceConfig, local::context::ServiceContext};

use super::server_stat::{Score, ServerStat};

#[cfg(feature = "tuic")]
use shadowsocks::{config::ServerProtocol, tuic::client as tuic};

/// Server's statistic score
pub struct ServerScore {
    stat_data: Mutex<ServerStat>,
    score: AtomicU32,
}

impl ServerScore {
    /// Create a `ServerScore`
    pub fn new(user_weight: f32, max_server_rtt: Duration, check_window: Duration) -> ServerScore {
        let max_server_rtt = max_server_rtt.as_millis() as u32;
        assert!(max_server_rtt > 0);

        ServerScore {
            stat_data: Mutex::new(ServerStat::new(user_weight, max_server_rtt, check_window)),
            score: AtomicU32::new(u32::MAX),
        }
    }

    /// Get server's current statistic scores
    pub fn score(&self) -> u32 {
        self.score.load(Ordering::Acquire)
    }

    /// Append a `Score` into statistic and recalculate score of the server
    pub async fn push_score(&self, score: Score) -> u32 {
        let updated_score = {
            let mut stat = self.stat_data.lock().await;
            stat.push_score(score)
        };
        self.score.store(updated_score, Ordering::Release);
        updated_score
    }

    /// Report request failure of this server, which will eventually records an `Errored` score
    pub async fn report_failure(&self) -> u32 {
        self.push_score(Score::Errored).await
    }
}

impl Debug for ServerScore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerScore").field("score", &self.score()).finish()
    }
}

/// Identifer for a server
#[derive(Debug)]
pub struct ServerIdent {
    tcp_score: ServerScore,
    udp_score: ServerScore,
    svr_cfg: ServerInstanceConfig,
    connect_opts: ConnectOpts,

    #[cfg(feature = "tuic")]
    tuic_dispatcher: Option<Arc<tuic::Dispatcher>>,
}

impl ServerIdent {
    /// Create a `ServerIdent`
    pub fn new(
        context: Arc<ServiceContext>,
        svr_cfg: ServerInstanceConfig,
        max_server_rtt: Duration,
        check_window: Duration,
    ) -> io::Result<ServerIdent> {
        #[cfg(feature = "tuic")]
        let tuic_dispatcher = if let ServerProtocol::Tuic(tuic_config) = svr_cfg.config.protocol() {
            let server_addr = match svr_cfg.config.addr() {
                shadowsocks::ServerAddr::DomainName(domain, port) => tuic::ServerAddrWithName::DomainAddr {
                    domain: domain.clone(),
                    port: *port,
                },
                shadowsocks::ServerAddr::SocketAddr(addr) => {
                    let tuic_config = match tuic_config {
                        shadowsocks::config::TuicConfig::Client(c) => c,
                        shadowsocks::config::TuicConfig::Server(..) => unreachable!(),
                    };

                    let sni = match tuic_config.sni.as_ref() {
                        Some(sni) => sni,
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "server sni is not spected",
                            ))
                        }
                    };
                    tuic::ServerAddrWithName::SocketAddr {
                        addr: *addr,
                        name: sni.clone(),
                    }
                }
            };

            let config_provider: tuic::ConfigProvider = {
                let _context = context.clone();
                let tuic_config = tuic_config.clone();
                Box::new(move || {
                    #[cfg(feature = "local-fake-mode")]
                    let mut _tuic_cfg_buf = None;

                    #[allow(unused_mut)]
                    let mut effect_tuic_cfg = &tuic_config;

                    #[cfg(feature = "local-fake-mode")]
                    if let Some(fake_cfg) = context.fake_mode().is_param_error_for_tuic(&tuic_config) {
                        _tuic_cfg_buf = Some(fake_cfg);
                        effect_tuic_cfg = _tuic_cfg_buf.as_ref().unwrap();
                    }

                    let effect_tuic_cfg = match effect_tuic_cfg {
                        shadowsocks::config::TuicConfig::Client(c) => c,
                        shadowsocks::config::TuicConfig::Server(..) => unreachable!(),
                    };

                    let config = tuic::Config::new(effect_tuic_cfg)?;
                    io::Result::Ok(config)
                })
            };

            Some(Arc::new(tuic::Dispatcher::new(
                context.context(),
                server_addr,
                config_provider,
                context.connect_opts_ref().clone(),
            )))
        } else {
            None
        };

        #[allow(unused_mut)]
        let mut connect_opts = context.connect_opts_ref().clone();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(fwmark) = svr_cfg.outbound_fwmark {
            connect_opts.fwmark = Some(fwmark);
        }

        if let Some(bind_local_addr) = svr_cfg.outbound_bind_addr {
            connect_opts.bind_local_addr = Some(bind_local_addr);
        }

        if let Some(ref bind_interface) = svr_cfg.outbound_bind_interface {
            connect_opts.bind_interface = Some(bind_interface.clone());
        }
        
        Ok(ServerIdent {
            tcp_score: ServerScore::new(svr_cfg.config.weight().tcp_weight(), max_server_rtt, check_window),
            udp_score: ServerScore::new(svr_cfg.config.weight().udp_weight(), max_server_rtt, check_window),
            svr_cfg,
            connect_opts,
            #[cfg(feature = "tuic")]
            tuic_dispatcher,
        })
    }

    pub fn connect_opts_ref(&self) -> &ConnectOpts {
        &self.connect_opts
    }

    pub fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg.config
    }

    pub fn server_config_mut(&mut self) -> &mut ServerConfig {
        &mut self.svr_cfg.config
    }

    pub fn server_instance_config(&self) -> &ServerInstanceConfig {
        &self.svr_cfg
    }

    pub fn tcp_score(&self) -> &ServerScore {
        &self.tcp_score
    }

    pub fn udp_score(&self) -> &ServerScore {
        &self.udp_score
    }

    #[cfg(feature = "tuic")]
    pub fn tuic_dispatcher(&self) -> Option<&Arc<tuic::Dispatcher>> {
        self.tuic_dispatcher.as_ref()
    }
}
