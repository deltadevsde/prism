use thiserror::Error;

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("Telemetry initialization error: {0}")]
    InitializationError(String),
}
