use crate::{error::TelemetryError, metrics_registry::init_metrics_registry};

use opentelemetry::global::{self};
use opentelemetry_sdk::{logs::SdkLoggerProvider, metrics::SdkMeterProvider};
use prism_telemetry::{
    config::TelemetryConfig,
    logs::setup_log_subscriber,
    telemetry::{build_resource, init_telemetry, set_global_attributes, shutdown_telemetry},
};

/// An active telemetry system instance for a Prism node.
///
/// This struct manages the lifecycle of OpenTelemetry providers and handles
/// metrics collection, distributed tracing, and structured logging. It should
/// be created once during node initialization and properly shut down before
/// node termination to ensure data is flushed to configured exporters.
pub struct TelemetryInstance {
    /// Configuration used to initialize this telemetry instance.
    /// Retained for proper cleanup and debugging.
    config: TelemetryConfig,

    /// OpenTelemetry metrics provider for collecting and exporting metrics.
    /// None if metrics collection is disabled or failed to initialize.
    meter_provider: Option<SdkMeterProvider>,

    /// OpenTelemetry logging provider for structured log export.
    /// None if log export is disabled or failed to initialize.
    log_provider: Option<SdkLoggerProvider>,
}

impl TelemetryInstance {
    /// Gracefully shuts down the telemetry system, flushing all pending data
    /// and cleaning up resources. Should be called before node termination.
    /// This method blocks briefly to ensure data is exported successfully.
    pub fn shutdown(self) {
        shutdown_telemetry(self.config, self.meter_provider, self.log_provider);
    }
}

/// Creates a telemetry system instance with the given configuration and attributes.
///
/// This function initializes OpenTelemetry providers for metrics and logging based on
/// the provided configuration, and returns a [`TelemetryInstance`] that manages their lifecycle.
///
/// See the crate-level documentation for usage examples and integration patterns.
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
