use crate::config::{ServerProtocol, ServerProtocolType, TransportType};

pub enum TrafficWay {
    Send,
    Recv,
}

impl TrafficWay {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Send => "tx",
            Self::Recv => "rx",
        }
    }
}

pub enum TrafficNet {
    Tcp,
    Udp,
}

impl TrafficNet {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone)]
pub enum ProtocolInfo {
    SS {
        method: String,
    },
    #[cfg(feature = "trojan")]
    Trojan,
    #[cfg(feature = "vless")]
    Vless,
    #[cfg(feature = "tuic")]
    Tuic {
        cc: &'static str,
    },
}

impl ProtocolInfo {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SS { .. } => ServerProtocolType::SS.name(),
            #[cfg(feature = "trojan")]
            Self::Trojan => ServerProtocolType::Trojan.name(),
            #[cfg(feature = "vless")]
            Self::Vless => ServerProtocolType::Vless.name(),
            #[cfg(feature = "tuic")]
            Self::Tuic { .. } => ServerProtocolType::Tuic.name(),
        }
    }
}

impl From<&ServerProtocol> for ProtocolInfo {
    fn from(value: &ServerProtocol) -> Self {
        match value {
            ServerProtocol::SS(ss_cfg) => ProtocolInfo::SS {
                method: ss_cfg.method().to_string(),
            },
            #[cfg(feature = "trojan")]
            ServerProtocol::Trojan(..) => ProtocolInfo::Trojan,
            #[cfg(feature = "vless")]
            ServerProtocol::Vless(..) => ProtocolInfo::Vless,
            #[cfg(feature = "tuic")]
            ServerProtocol::Tuic(tuic_cfg) => match tuic_cfg {
                crate::config::TuicConfig::Client(..) => unimplemented!(),
                crate::config::TuicConfig::Server((tuic_cfg, ..)) => ProtocolInfo::Tuic {
                    cc: tuic_cfg.congestion_controller.name(),
                },
            },
        }
    }
}

#[derive(Clone)]
pub struct BuContext {
    protocol: ProtocolInfo,
    transport: Option<TransportType>,
}

impl BuContext {
    pub fn new(protocol: ProtocolInfo, transport: Option<TransportType>) -> Self {
        Self { protocol, transport }
    }

    pub fn protocol(&self) -> &ProtocolInfo {
        &self.protocol
    }

    pub fn transport(&self) -> Option<&TransportType> {
        self.transport.as_ref()
    }

    pub fn increment_bu_client(&self) {
        let protocol = self.protocol.name();
        let trans = self.transport.as_ref().map(|t| t.name()).unwrap_or("none");

        match self.protocol {
            ProtocolInfo::SS { ref method } => {
                increment_gauge!(super::METRIC_BU_CLIENT, 1.0, "proto" => protocol, "trans" => trans, "ss_method" => method.clone())
            }
            #[cfg(feature = "trojan")]
            ProtocolInfo::Trojan => {
                increment_gauge!(super::METRIC_BU_CLIENT, 1.0, "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "vless")]
            ProtocolInfo::Vless => {
                increment_gauge!(super::METRIC_BU_CLIENT, 1.0, "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "tuic")]
            ProtocolInfo::Tuic { cc } => {
                increment_gauge!(super::METRIC_BU_CLIENT, 1.0, "proto" => protocol, "trans" => trans, "tuic_cc" => cc)
            }
        }
    }

    pub fn decrement_bu_client(&self) {
        let protocol = self.protocol.name();
        let trans = self.transport.as_ref().map(|t| t.name()).unwrap_or("none");

        match self.protocol {
            ProtocolInfo::SS { ref method } => {
                decrement_gauge!(super::METRIC_BU_CLIENT, 1.0, "proto" => protocol, "trans" => trans, "ss_method" => method.clone())
            }
            #[cfg(feature = "trojan")]
            ProtocolInfo::Trojan => {
                decrement_gauge!(super::METRIC_BU_CLIENT, 1.0, "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "vless")]
            ProtocolInfo::Vless => {
                decrement_gauge!(super::METRIC_BU_CLIENT, 1.0, "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "tuic")]
            ProtocolInfo::Tuic { cc } => {
                decrement_gauge!(super::METRIC_BU_CLIENT, 1.0, "proto" => protocol, "trans" => trans, "tuic_cc" => cc)
            }
        }
    }

    pub fn increment_conn_error(&self, reason: &'static str) {
        let protocol = self.protocol.name();
        let trans = self.transport.as_ref().map(|t| t.name()).unwrap_or("none");

        match self.protocol {
            ProtocolInfo::SS { ref method } => {
                increment_counter!(super::METRIC_TCP_CONN_ERR_TOTAL, "reason" => reason, "proto" => protocol, "trans" => trans, "ss_method" => method.clone())
            }
            #[cfg(feature = "trojan")]
            ProtocolInfo::Trojan => {
                increment_counter!(super::METRIC_TCP_CONN_ERR_TOTAL, "reason" => reason, "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "vless")]
            ProtocolInfo::Vless => {
                increment_counter!(super::METRIC_TCP_CONN_ERR_TOTAL, "reason" => reason, "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "tuic")]
            ProtocolInfo::Tuic { cc } => {
                increment_counter!(super::METRIC_TCP_CONN_ERR_TOTAL, "reason" => reason, "proto" => protocol, "trans" => trans, "tuic_cc" => cc)
            }
        }
    }

    pub fn count_traffic_bps(&self, key: &'static str, bps: f64, net: TrafficNet, way: TrafficWay) {
        let protocol = self.protocol.name();
        let trans = self.transport.as_ref().map(|t| t.name()).unwrap_or("none");

        match self.protocol {
            ProtocolInfo::SS { ref method } => {
                gauge!(key, bps, "way" => way.name(), "net" => net.name(), "proto" => protocol, "trans" => trans, "ss_method" => method.clone())
            }
            #[cfg(feature = "trojan")]
            ProtocolInfo::Trojan => {
                gauge!(key, bps, "way" => way.name(), "net" => net.name(), "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "vless")]
            ProtocolInfo::Vless => {
                gauge!(key, bps, "way" => way.name(), "net" => net.name(), "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "tuic")]
            ProtocolInfo::Tuic { cc } => {
                gauge!(key, bps, "way" => way.name(), "net" => net.name(), "proto" => protocol, "trans" => trans, "tuic_cc" => cc)
            }
        }
    }

    pub fn count_traffic(&self, key: &'static str, count: u64, net: TrafficNet, way: TrafficWay) {
        let protocol = self.protocol.name();
        let trans = self.transport.as_ref().map(|t| t.name()).unwrap_or("none");

        match self.protocol {
            ProtocolInfo::SS { ref method } => {
                counter!(key, count, "way" => way.name(), "net" => net.name(), "proto" => protocol, "trans" => trans, "ss_method" => method.clone())
            }
            #[cfg(feature = "trojan")]
            ProtocolInfo::Trojan => {
                counter!(key, count, "way" => way.name(), "net" => net.name(), "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "vless")]
            ProtocolInfo::Vless => {
                counter!(key, count, "way" => way.name(), "net" => net.name(), "proto" => protocol, "trans" => trans)
            }
            #[cfg(feature = "tuic")]
            ProtocolInfo::Tuic { cc } => {
                counter!(key, count, "way" => way.name(), "net" => net.name(), "proto" => protocol, "trans" => trans, "tuic_cc" => cc)
            }
        }
    }
}
