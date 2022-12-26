use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;

pub fn install_push_gateway(url: &url::Url, job: &str, instance: Option<&str>, timeout: Duration) {
    let mut url = url.clone();
    url.path_segments_mut()
        .unwrap()
        .pop()
        .push("metrics")
        .push("job")
        .push(job);

    if let Some(instance) = instance {
        url.path_segments_mut().unwrap().push("instance").push(instance);
    }

    PrometheusBuilder::new()
        .with_push_gateway(url, timeout)
        .expect("push gateway endpoint should be valid")
        .idle_timeout(
            MetricKindMask::COUNTER | MetricKindMask::HISTOGRAM,
            Some(Duration::from_secs(10)),
        )
        .install()
        .expect("failed to install Prometheus recorder");
}
