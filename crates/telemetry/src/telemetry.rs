use crate::metrics;
use crate::logs;
use crate::config::TelemetryConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use crate::metrics::init_metrics;
use opentelemetry::KeyValue;
use std::sync::Mutex;
use lazy_static::lazy_static;
use std::error::Error;
use tracing::info;

lazy_static! {
    static ref GLOBAL_ATTRIBUTES: Mutex<Vec<KeyValue>> = Mutex::new(Vec::new());
}

pub fn init_telemetry(config: &TelemetryConfig, resource: Resource) -> Result<(Option<SdkMeterProvider>, Option<SdkLoggerProvider>), Box<dyn Error>> {
    info!("Initializing telemetry with configuration: metrics_enabled={}, logs_enabled={}",
        config.metrics.enabled, config.logs.enabled);

    // Initialize metrics if enabled
    let meter_provider = if config.metrics.enabled {
        match init_metrics(&config.metrics, resource.clone()) {
            Ok(provider) => {
                info!("Metrics initialized successfully with endpoint: {}", config.metrics.endpoint);
                Some(provider)
            },
            Err(e) => {
                tracing::error!("Failed to initialize metrics: {}", e);
                return Err(e);
            }
        }
    } else {
        info!("Metrics are disabled, skipping metrics initialization");
        None
    };

    // Initialize logs if enabled
    let log_provider = if config.logs.enabled {
        match logs::init_logs(&config.logs, resource.clone()) {
            Ok(provider) => {
                info!("Logs initialized successfully with endpoint: {}", config.logs.endpoint);
                Some(provider)
            },
            Err(e) => {
                tracing::error!("Failed to initialize logs: {}", e);
                return Err(e);
            }
        }
    } else {
        info!("Logs are disabled, skipping logs initialization");
        None
    };

    info!("Telemetry initialization completed successfully");
    Ok((meter_provider, log_provider))
}

pub fn shutdown_telemetry(
    config: TelemetryConfig,
    meter_provider: Option<SdkMeterProvider>,
    log_provider: Option<SdkLoggerProvider>,
) {
    info!("Shutting down telemetry");

    if config.metrics.enabled {
        if let Some(provider) = meter_provider {
            if let Err(e) = metrics::shutdown_metrics(provider) {
                tracing::warn!("Error shutting down metrics: {}", e);
            }
        }
    }

    if config.logs.enabled {
        if let Some(provider) = log_provider {
            if let Err(e) = logs::shutdown_logs(provider) {
                tracing::warn!("Error shutting down logs: {}", e);
            }
        }
    }
}

// Get the resource for telemetry with global labels
pub fn build_resource(service_name: String, attributes: Vec<KeyValue>) -> Resource {
    let mut resource_builder = Resource::builder()
        .with_service_name(service_name);

    // Add all global labels to the resource
    for attribute in attributes {
        resource_builder = resource_builder.with_attribute(attribute);
    }

    resource_builder.build()
}

pub fn set_global_attributes(attributes: Vec<KeyValue>) {
    if let Ok(mut global_attrs) = GLOBAL_ATTRIBUTES.lock() {
        *global_attrs = attributes;
    } else {
        tracing::error!("Failed to acquire lock for setting global attributes");
    }
}

pub fn build_attributes(attributes: Vec<(String, String)>) -> Vec<KeyValue> {
    let mut new_attrs = match GLOBAL_ATTRIBUTES.lock() {
        Ok(global_attrs) => global_attrs.clone(),
        Err(_) => {
            tracing::error!("Failed to acquire lock for reading global attributes");
            Vec::new()
        }
    };
    new_attrs.extend(attributes.into_iter().map(|(k, v)| KeyValue::new(k, v)));
    new_attrs
}
