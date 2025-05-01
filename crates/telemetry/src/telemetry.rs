use crate::metrics;
use crate::logs;
use crate::config::TelemetryConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use crate::metrics::init_metrics;
use std::error::Error;
use tracing::info;
use opentelemetry::KeyValue;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref GLOBAL_ATTRIBUTES: Mutex<Vec<KeyValue>> = Mutex::new(Vec::new());
}

pub fn init_telemetry(config: &TelemetryConfig, resource: Resource) -> Result<Option<SdkMeterProvider>, Box<dyn Error>> {
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
    if config.logs.enabled {
        logs::init_logs(&config.logs);
        info!("Logs initialized successfully with endpoint: {}", config.logs.endpoint);
    } else {
        info!("Logs are disabled, skipping logs initialization");
    }

    info!("Telemetry initialization completed successfully");
    Ok(meter_provider)
}

pub fn shutdown_telemetry(config: &TelemetryConfig, meter_provider: Option<SdkMeterProvider>) {
    info!("Shutting down telemetry");

    if config.metrics.enabled {
        if let Some(provider) = meter_provider {
            let _ = metrics::shutdown_metrics(provider);
        }
    }
    
    if config.logs.enabled {
        logs::shutdown_logs();
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

pub fn build_attributes(attributes: Vec<KeyValue>) -> Vec<KeyValue> {
    let mut new_attrs = match GLOBAL_ATTRIBUTES.lock() {
        Ok(global_attrs) => global_attrs.clone(),
        Err(_) => {
            tracing::error!("Failed to acquire lock for reading global attributes");
            Vec::new()
        }
    };
    new_attrs.extend(attributes);
    new_attrs
}
