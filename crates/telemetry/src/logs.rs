use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{
    LogExporter,
    Protocol,
    WithExportConfig,
    WithHttpConfig,
};
use opentelemetry_sdk::{
    logs::SdkLoggerProvider,
    Resource,
};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use std::time::Duration;
use tracing::{info, error};
use crate::config::LogsConfig;
use std::error::Error;
use base64;
use base64::Engine;
use std::collections::HashMap;

// ===== LOGS FUNCTIONALITY =====

pub fn init_logs(logs_config: &LogsConfig, resource: Resource) -> Result<SdkLoggerProvider, Box<dyn Error + Send + Sync + 'static>> {
    // Build the complete endpoint URL with proper path handling
    let endpoint_url = if logs_config.endpoint.ends_with("v1/logs") || logs_config.endpoint.ends_with("v1/logs/") {
        logs_config.endpoint.to_string()
    } else if logs_config.endpoint.ends_with('/') {
        format!("{}v1/logs", logs_config.endpoint)
    } else {
        format!("{}/v1/logs", logs_config.endpoint)
    };

    info!("Initializing logs with endpoint: {}", endpoint_url);

    // Build the exporter with basic configuration
    let mut builder = LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(&endpoint_url)
        .with_timeout(Duration::from_secs(5)); // Add timeout to detect backend unavailability

    // Add basic authentication if enabled
    if logs_config.auth.enabled {
        let auth_string = format!("{}:{}", logs_config.auth.username, logs_config.auth.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(auth_string);
        let auth_header = format!("Basic {}", encoded);

        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), auth_header);
        builder = builder.with_headers(headers);
    }

    let exporter = match builder.build() {
        Ok(exporter) => exporter,
        Err(e) => {
            error!("Failed to build log exporter: {}. Logs will only be available locally.", e);
            return Err(Box::new(std::io::Error::other(
                format!("Failed to build log exporter: {}", e))));
        }
    };

    // The resource already contains the global labels from get_resource()
    let final_resource = resource;

    let provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(final_resource)
        .build();

    Ok(provider)
}

/// Creates an EnvFilter that respects the RUST_LOG environment variable
/// Falls back to sensible defaults if RUST_LOG is not set
pub fn create_env_filter() -> EnvFilter {
    // Start with the environment variable or default to "info"
    EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| {
        // If RUST_LOG is not set, use these defaults
        EnvFilter::new("info")
            .add_directive("hyper=off".parse().unwrap())
            .add_directive("tonic=off".parse().unwrap())
            .add_directive("h2=off".parse().unwrap())
            .add_directive("reqwest=off".parse().unwrap())
            .add_directive("pyroscope=info".parse().unwrap())
            .add_directive("pprof=info".parse().unwrap())
    })
}

/// Set up a configurable tracing subscriber that can handle both logs and spans
/// with support for global labels
pub fn setup_log_subscriber(
    enable_logs: bool,
    logger_provider: Option<&SdkLoggerProvider>
) {
    // Create the console output layer with environment-based filter
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_filter(create_env_filter());

    // Set up the subscriber based on configuration
    if enable_logs && logger_provider.is_some() {
        // Create the OpenTelemetry layer for logs
        let otel_layer = OpenTelemetryTracingBridge::new(logger_provider.unwrap())
            .with_filter(create_env_filter());

        // Initialize the registry with both layers
        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(otel_layer)
            .init();

    } else {
        // Initialize the registry with just the console layer
        tracing_subscriber::registry()
            .with(fmt_layer)
            .init();
    }
}

pub fn shutdown_logs(provider: SdkLoggerProvider) -> Result<(), String> {
    if let Err(e) = provider.shutdown() {
        error!("Error shutting down logger provider: {}", e);
        return Err(format!("logger provider: {}", e));
    }
    Ok(())
}
