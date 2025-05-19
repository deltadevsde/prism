use std::io::Error;

use crate::metrics_registry::init_metrics_registry;

use opentelemetry::global::{self};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prism_telemetry::telemetry::{init_telemetry, build_resource, set_global_attributes};
use prism_telemetry::logs::setup_log_subscriber;
use prism_telemetry::config::TelemetryConfig;

pub fn init(telemetry_config: TelemetryConfig, attributes: Vec<(String, String)>) -> Result<(Option<SdkMeterProvider>, Option<SdkLoggerProvider>), Error> {
    // Initialize the telemetry system

    let mut attributes = attributes.clone();
    attributes.extend(telemetry_config.global_labels.labels.clone());

    set_global_attributes(attributes.clone());

    let resource = build_resource("prism-messenger-server".to_string(), attributes);

    let (meter_provider, log_provider) = init_telemetry(&telemetry_config, resource)
    .map_err(|e| Error::other(format!("Failed to initialize telemetry: {}", e)))?;

    // Initialize tracing subscriber, fallback to stdout/stderr if no log provider
    setup_log_subscriber(
      telemetry_config.logs.enabled,
      log_provider.as_ref(),
    );

    if let Some(ref provider) = meter_provider {
        global::set_meter_provider(provider.clone());

        // Initialize the metrics registry after setting the global meter provider
        init_metrics_registry();
    } else {
        tracing::warn!("No meter provider available, metrics will not be recorded");
    }

    Ok((meter_provider, log_provider))
}
