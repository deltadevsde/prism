use std::io::Error;

use crate::metrics_registry::init_metrics_registry;

use opentelemetry::global::{self};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prism_telemetry::telemetry::{init_telemetry, build_resource, set_global_attributes};
use prism_telemetry::logs::setup_log_subscriber;
use prism_telemetry::config::TelemetryConfig;

/// Initializes the telemetry system with metrics and logging providers.
///
/// Merges the provided attributes with global labels from the telemetry configuration, sets them as global attributes, and builds a resource descriptor. Initializes telemetry using the configuration and resource, sets up the global meter provider and metrics registry if available, and configures the log subscriber if a logger provider is present.
///
/// # Parameters
/// - `attributes`: Initial global attribute key-value pairs to be merged with configuration labels.
///
/// # Returns
/// A tuple containing optional meter and logger providers on success, or an I/O error if initialization fails.
///
/// # Examples
///
/// ```
/// let config = TelemetryConfig::default();
/// let attrs = vec![("env".to_string(), "production".to_string())];
/// let result = init(config, attrs);
/// assert!(result.is_ok());
/// ```
pub fn init(telemetry_config: TelemetryConfig, attributes: Vec<(String, String)>) -> Result<(Option<SdkMeterProvider>, Option<SdkLoggerProvider>), Error> {
    // Initialize the telemetry system

    let mut attributes = attributes.clone();
    attributes.extend(telemetry_config.global_labels.labels.clone());

    set_global_attributes(attributes.clone());

    let resource = build_resource("prism".to_string(), attributes);

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
