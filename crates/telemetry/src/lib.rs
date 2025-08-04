pub mod error;
pub mod metrics_registry;

mod factory;

pub use factory::{TelemetryInstance, create_telemetry};
