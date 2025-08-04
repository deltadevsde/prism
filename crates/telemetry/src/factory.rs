use crate::{error::TelemetryError, metrics_registry::init_metrics_registry};

use opentelemetry::global::{self};
use opentelemetry_sdk::{logs::SdkLoggerProvider, metrics::SdkMeterProvider};
use prism_telemetry::{
    config::TelemetryConfig,
    logs::setup_log_subscriber,
    telemetry::{build_resource, init_telemetry, set_global_attributes, shutdown_telemetry},
};

/// Represents an instance of the telemetry system, holding configuration and providers.
pub struct TelemetryInstance {
    config: TelemetryConfig,
    meter_provider: Option<SdkMeterProvider>,
    log_provider: Option<SdkLoggerProvider>,
}

impl TelemetryInstance {
    /// Shuts down the telemetry system.
    pub fn shutdown(self) {
        shutdown_telemetry(self.config, self.meter_provider, self.log_provider);
    }
}

/// Initializes the telemetry system with metrics and logging providers.
///
/// Merges the provided attributes with global labels from the telemetry configuration, sets them as
/// global attributes, and builds a resource descriptor. Initializes telemetry using the
/// configuration and resource, sets up the global meter provider and metrics registry if available,
/// and configures the log subscriber if a logger provider is present.
///
/// # Parameters
/// - `attributes`: Initial global attribute key-value pairs to be merged with configuration labels.
///
/// # Returns
/// A tuple containing optional meter and logger providers on success, or an I/O error if
/// initialization fails.
///
/// # Examples
///
/// ```
/// let config = TelemetryConfig::default();
/// let attrs = vec![("env".to_string(), "production".to_string())];
/// let result = init(config, attrs);
/// assert!(result.is_ok());
/// ```
pub fn create_telemetry(
    telemetry_config: &TelemetryConfig,
    attributes: Vec<(String, String)>,
) -> Result<TelemetryInstance, TelemetryError> {
    // Initialize the telemetry system

    let mut attributes = attributes.clone();
    attributes.extend(telemetry_config.global_labels.labels.clone());

    set_global_attributes(attributes.clone());

    let resource = build_resource("prism".to_string(), attributes);

    let (meter_provider, log_provider) =
        init_telemetry(telemetry_config, resource).map_err(|e| {
            TelemetryError::InitializationError(format!("Failed to initialize telemetry: {}", e))
        })?;

    // Initialize tracing subscriber, fallback to stdout/stderr if no log provider
    setup_log_subscriber(telemetry_config.logs.enabled, log_provider.as_ref());

    if let Some(ref provider) = meter_provider {
        global::set_meter_provider(provider.clone());

        // Initialize the metrics registry after setting the global meter provider
        init_metrics_registry();
    } else {
        tracing::warn!("No meter provider available, metrics will not be recorded");
    }

    Ok(TelemetryInstance {
        config: telemetry_config.clone(),
        meter_provider,
        log_provider,
    })
}
