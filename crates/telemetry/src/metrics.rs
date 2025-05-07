use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;
use std::error::Error;
use tracing::{info, error};
use base64;
use base64::Engine;
use std::collections::HashMap;
use std::time::Duration;

use crate::config::MetricsConfig;

pub fn init_metrics(metrics_config: &MetricsConfig, resource: Resource) -> Result<SdkMeterProvider, Box<dyn Error + Send + Sync + 'static>> {
    // Build the complete endpoint URL with proper path handling
    let endpoint_url = if metrics_config.endpoint.ends_with("v1/metrics") || metrics_config.endpoint.ends_with("v1/metrics/") {
        metrics_config.endpoint.to_string()
    } else if metrics_config.endpoint.ends_with('/') {
        format!("{}v1/metrics", metrics_config.endpoint)
    } else {
        format!("{}/v1/metrics", metrics_config.endpoint)
    };

    info!("Initializing metrics with endpoint: {}", endpoint_url);

    // Build the exporter with basic configuration
    let mut builder = MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(&endpoint_url)
        .with_timeout(Duration::from_secs(5)); // Add timeout to detect backend unavailability

    // Add basic authentication if enabled
    if metrics_config.auth.enabled {
        let auth_string = format!("{}:{}", metrics_config.auth.username, metrics_config.auth.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(auth_string);
        let auth_header = format!("Basic {}", encoded);

        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), auth_header);
        builder = builder.with_headers(headers);
    }

    let exporter = match builder.build() {
        Ok(exporter) => exporter,
        Err(e) => {
            error!("Failed to build metric exporter: {}. Metrics will not be sent to backend.", e);
            return Err(Box::new(std::io::Error::other(
                format!("Failed to build metric exporter: {}", e))));
        }
    };

    // Configure the meter provider
    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        .with_resource(resource)
        .build();

    Ok(provider)
}

pub fn shutdown_metrics(provider: SdkMeterProvider) -> Result<(), String> {
    if let Err(e) = provider.shutdown() {
        error!("Error shutting down meter provider: {}", e);
        return Err(format!("meter provider: {}", e));
    }
    Ok(())
}
