use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Basic auth configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BasicAuth {
    pub enabled: bool,
    pub username: String,
    pub password: String,
}

// Configuration for metrics
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub auth: BasicAuth,
}

// Configuration for logs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogsConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub auth: BasicAuth,
}

// Configuration for traces
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TracesConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub auth: BasicAuth,
}

// Configuration for profiles
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProfilesConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub auth: BasicAuth,
}

// Global labels to be added to all telemetry types
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TelemetryLabels {
    pub labels: HashMap<String, String>,
}


// Configuration for telemetry components
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TelemetryConfig {
    pub metrics: MetricsConfig,
    pub logs: LogsConfig,
    pub traces: TracesConfig,
    pub profiles: ProfilesConfig,
    pub global_labels: TelemetryLabels,
}


pub fn get_default_telemetry_config() -> TelemetryConfig {
    TelemetryConfig {
        metrics: MetricsConfig {
            enabled: false,
            endpoint: "https://alloy.prism.boo".to_string(),
            auth: BasicAuth {
                enabled: false,
                username: "".to_string(),
                password: "".to_string(),
            },
        },
        logs: LogsConfig {
            enabled: false,
            endpoint: "https://alloy.prism.boo".to_string(),
            auth: BasicAuth {
                enabled: false,
                username: "".to_string(),
                password: "".to_string(),
            },
        },
        traces: TracesConfig {
            enabled: false,
            endpoint: "https://alloy.prism.boo".to_string(),
            auth: BasicAuth {
                enabled: false,
                username: "".to_string(),
                password: "".to_string(),
            },
        },
        profiles: ProfilesConfig {
            enabled: false,
            endpoint: "https://alloy.prism.boo".to_string(),
            auth: BasicAuth {
                enabled: false,
                username: "".to_string(),
                password: "".to_string(),
            },
        },
        global_labels: TelemetryLabels {
            labels: HashMap::new(),
        },
    }
}