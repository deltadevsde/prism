use prism_errors::{DataAvailabilityError, DatabaseError};
use prism_telemetry_registry::error::TelemetryError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Config failed: {0}")]
    ConfigFailed(String),
    #[error("Data availability error: {0}")]
    DataAvailabilityFailed(#[from] DataAvailabilityError),
    #[error("Database error: {0}")]
    DatabaseFailed(#[from] DatabaseError),
    #[error("Node error: {0}")]
    NodeError(String),
}

impl From<TelemetryError> for CliError {
    fn from(err: TelemetryError) -> Self {
        CliError::ConfigFailed(format!("Telemetry error: {}", err))
    }
}
