//! Logging facilities
use cfg_if::cfg_if;
use std::path::Path;

pub struct Guard {}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(feature = "logging-remote")]
        opentelemetry::global::shutdown_tracer_provider();
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

    let is_self_module = move |target: &str| target.starts_with(bin_name) || target.starts_with("shadowsocks");
    let filter_fn = filter_fn(move |metadata| {
        if let Some(other_level) = other_level {
            metadata.level() <= &other_level || is_self_module(metadata.target())
        } else {
            is_self_module(metadata.target())
        }
    })
    .with_max_level_hint(level);

    let guard = Guard {};

    let subscriber = tracing_subscriber::registry();

    cfg_if! {
        if #[cfg(feature = "logging-remote")] {
            let subscriber = subscriber.with(config.log_remote_url.as_ref().map(|url| {
                opentelemetry::global::set_text_map_propagator(opentelemetry_jaeger::Propagator::new());

                let mut base_url = url.clone();
                base_url.set_password(None).expect("jaeger url");
                base_url.set_username("").expect("jaeger url");

                // Install a new OpenTelemetry trace pipeline
                let mut tracer = opentelemetry_jaeger::new_collector_pipeline()
                    .with_service_name("sfox-miner")
                    .with_hyper()
                    .with_endpoint(format!("{}", base_url)); //"http://127.0.0.1:14268/api/traces"

                if !url.username().is_empty() {
                    tracer = tracer.with_username(url.username());
                }

                if url.password().is_some() {
                    tracer = tracer.with_password(url.password().unwrap());
                }

                let tracer = tracer.install_batch(opentelemetry::runtime::Tokio)
                    .expect("jaeger");

                // Create a tracing layer with the configured tracer
                tracing_opentelemetry::layer().with_tracer(tracer).with_filter(filter_fn.clone())
            }));
        }
    }

    // 控制台输出
    let subscriber = subscriber.with({
        let append = tracing_subscriber::fmt::layer().with_target(false);
        if config.format.without_time {
            append.without_time().with_filter(filter_fn.clone()).boxed()
        } else {
            append.with_filter(filter_fn.clone()).boxed()
        }
    });

    // 文件输出
    let subscriber = subscriber.with(config.log_template.as_ref().map(|log_template| {
        let file_appender = tracing_appender::rolling::daily(
            log_template.parent().unwrap_or(Path::new(".")),
            log_template.file_name().expect("logging"),
        );

        let layer = tracing_subscriber::fmt::layer();

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let layer = layer.with_ansi(false);

        layer.with_writer(file_appender)
            .with_filter(filter_fn.clone())
            .boxed()
    }));

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
pub fn init_with_default(bin_name: &'static str) {
    init_with_config(bin_name, &LogConfig::default());
}
