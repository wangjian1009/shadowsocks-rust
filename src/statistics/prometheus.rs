use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;

pub fn install_push_gateway(
    url: &url::Url,
    job: &str,
    instance: Option<&str>,
    timeout: Duration,
    tags: Option<Vec<&str>>,
) {
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

    if let Some(tags) = tags {
        for tag in tags {
            let mut parts = tag.split('=');
            if let Some(key) = parts.next() {
                let value = parts.next();
                url.path_segments_mut().unwrap().push(key).push(value.unwrap_or("1"));
            }
        }
    }

    PrometheusBuilder::new()
        .with_push_gateway(url, timeout)
        .expect("push gateway endpoint should be valid")
        .idle_timeout(
            MetricKindMask::COUNTER | MetricKindMask::HISTOGRAM,
            Some(Duration::from_secs(timeout.as_secs() * 3)),
        )
        .install()
        .expect("failed to install Prometheus recorder");
}
