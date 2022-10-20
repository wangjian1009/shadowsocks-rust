//! Logging facilities
use cfg_if::cfg_if;

pub struct Guard {
    need_wait: bool,
}

impl Guard {
    pub async fn close(self) {
        #[cfg(feature = "logging-jaeger")]
        opentelemetry::global::shutdown_tracer_provider();

        if self.need_wait {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
}

use crate::config::LogConfig;
use tracing_subscriber::{
    filter::{filter_fn, LevelFilter},
    layer::Layer,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// Initialize logger with default configuration
pub fn init_with_config(bin_name: &'static str, config: &LogConfig) -> Guard {
    let (level, other_level) = match config.level {
        0 => (LevelFilter::INFO, LevelFilter::OFF),
        1 => (LevelFilter::DEBUG, LevelFilter::OFF),
        2 => (LevelFilter::TRACE, LevelFilter::OFF),
        3 => (LevelFilter::TRACE, LevelFilter::DEBUG),
        _ => (LevelFilter::TRACE, LevelFilter::TRACE),
    };
    let other_level = other_level.into_level();

    let self_modules = vec![bin_name, "shadowsocks"];
    let is_self_module = move |target: &str| {
        for m in &self_modules {
            if target.starts_with(m) {
                return true;
            }
        }
        false
    };
    #[warn(unused_variables)]
    let filter_fn = filter_fn(move |metadata| {
        if metadata.target().starts_with("quinn") {
            return metadata.level() <= &LevelFilter::INFO;
        }

        if is_self_module(metadata.target()) {
            metadata.level() <= &level
        } else {
            if let Some(other_level) = other_level {
                metadata.level() <= &other_level
            } else {
                false
            }
        }
    })
    .with_max_level_hint(level);

    #[allow(unused_mut)]
    let mut guard = Guard { need_wait: false };

    let subscriber = tracing_subscriber::registry();

    // 控制台输出
    cfg_if! {
        if #[cfg(feature = "logging-console")] {
            let subscriber = subscriber.with({
                let append = tracing_subscriber::fmt::layer().with_target(false);

                #[cfg(target_os = "android")]
                let append = append.with_ansi(false);

                if config.format.without_time {
                    append.without_time().with_filter(filter_fn.clone()).boxed()
                } else {
                    append.with_filter(filter_fn.clone()).boxed()
                }
            });
        }
    }

    // oslog
    cfg_if! {
        if #[cfg(feature = "logging-oslog")] {
            let subscriber = subscriber.with({
                tracing_oslog::OsLogger::new("cc.sfox", bin_name).with_filter(filter_fn.clone())
            });
        }
    }

    cfg_if! {
        if #[cfg(feature = "logging-apm")] {
            let subscriber = subscriber.with(config.log_apm_url.as_ref().map(|url| {
                guard.need_wait = true;
                tracing_elastic_apm::new_layer(bin_name.to_string(), build_apm_config(url))
                    .expect("apm-server")
                    .with_filter(filter_fn.clone())
            }));
        }
    }

    cfg_if! {
        if #[cfg(feature = "logging-jaeger")] {
            let subscriber = subscriber.with(config.log_jaeger_url.as_ref().map(|url| {
                guard.need_wait = true;
                opentelemetry::global::set_text_map_propagator(opentelemetry_jaeger::Propagator::new());
                // Create a tracing layer with the configured tracer
                tracing_opentelemetry::layer().with_tracer(build_jaeger_tracer(bin_name, url)).with_filter(filter_fn.clone())
            }));
        }
    }

    // 文件输出
    cfg_if! {
        if #[cfg(feature = "logging-file")] {
            let subscriber = subscriber.with(config.log_template.as_ref().map(|log_template| {
                use std::path::Path;

                let file_appender = tracing_appender::rolling::daily(
                    log_template.parent().unwrap_or(Path::new(".")),
                    log_template.file_name().expect("logging"),
                );

                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_writer(file_appender)
                    .with_filter(filter_fn.clone()).boxed()
            }));
        }
    }

    // 指标采集
    // .with(
    //     // Add a filter to the metrics label that *only* enables
    //     // events whose targets start with `metrics`.
    //     metrics_layer.with_filter(filter::filter_fn(|metadata| metadata.target().starts_with("metrics"))),
    // )

    subscriber.init();

    guard
}

/// Init a default logger
pub fn init_with_default(bin_name: &'static str) -> Guard {
    init_with_config(bin_name, &LogConfig::default())
}

#[cfg(feature = "logging-apm")]
fn build_apm_config(url: &url::Url) -> tracing_elastic_apm::config::Config {
    use sysinfo::ProcessExt;
    use sysinfo::SystemExt;
    use tracing_elastic_apm::config::*;
    use tracing_elastic_apm::model::*;

    let config = if url.username().is_empty() {
        Config::new(url.to_string()).with_authorization(Authorization::SecretToken(
            "TFdlc3dZTUJTeWMxS3dKRzdnUlo6Z2lWTk5Td3FRWnF5VkxSeUFOWWpvZw==".to_string(),
        ))
    } else {
        let mut base_url = url.clone();
        base_url.set_username("").expect("apm-server");
        Config::new(base_url.to_string()).with_authorization(Authorization::SecretToken(url.username().to_owned()))
    };

    // namespace := os.Getenv("KUBERNETES_NAMESPACE")
    // podName := os.Getenv("KUBERNETES_POD_NAME")
    // podUID := os.Getenv("KUBERNETES_POD_UID")
    // nodeName := os.Getenv("KUBERNETES_NODE_NAME")

    let mut system = sysinfo::System::new();
    system.refresh_all();
    let process = system
        .process(sysinfo::get_current_pid().expect("apm-server"))
        .expect("apm-server");

    config
        .with_service(Service::new(
            /*version*/ Some(crate::VERSION.to_owned()),
            /*environment*/ Some("test".to_owned()),
            /*language*/
            Some(Language {
                name: "rust".to_owned(),
                version: None,
            }),
            /*runtime*/ None,
            /*framework*/ None,
            /*node*/
            Some(ServiceNode {
                configured_name: Some("test_node".to_string()),
            }),
        ))
        .with_system(System {
            architecture: None,
            hostname: system.host_name(),
            detected_hostname: None,
            configured_hostname: None,
            platform: system.name(),
            container: None,
            kubernetes: None,
        })
        .with_process(Process {
            pid: process.pid().into(),
            ppid: process.parent().map(|pid| pid.into()),
            title: Some(process.name().to_string()),
            argv: Some(process.cmd().iter().map(|v| v.clone()).collect()),
        })
        .allow_invalid_certificates(true)
}

#[cfg(feature = "logging-jaeger")]
fn build_jaeger_tracer(bin_name: &'static str, url: &url::Url) -> opentelemetry::sdk::trace::Tracer {
    let mut base_url = url.clone();
    base_url.set_password(None).expect("jaeger url");
    base_url.set_username("").expect("jaeger url");

    // Install a new OpenTelemetry trace pipeline
    let mut tracer = opentelemetry_jaeger::new_collector_pipeline()
        .with_service_name(bin_name.to_string())
        .with_hyper()
        .with_endpoint(base_url.to_string());

    if !url.username().is_empty() {
        tracer = tracer.with_username(url.username());
    }

    if url.password().is_some() {
        tracer = tracer.with_password(url.password().unwrap());
    }

    tracer.install_batch(opentelemetry::runtime::Tokio).expect("jaeger")
}
