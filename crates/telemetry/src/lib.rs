#![feature(coverage_attribute)]
//! # Prism Telemetry
//!
//! This crate provides telemetry infrastructure for Prism nodes, including metrics collection,
//! distributed tracing, and structured logging using OpenTelemetry standards.
//!
//! ## Overview
//!
//! The telemetry system enables:
//! - **Metrics Collection**: Custom metrics for node performance and behavior
//! - **Distributed Tracing**: Request tracing across system components
//! - **Structured Logging**: Configurable log levels and export destinations
//! - **Multiple Exporters**: Support for various telemetry backends
//!
//! ## Quick Start
//!
//! ### Basic Setup
//!
//! ```rust,no_run
//! use prism_telemetry_registry::{TelemetryInstance, create_telemetry};
//! use prism_telemetry::config::TelemetryConfig;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure telemetry
//!     let config = TelemetryConfig::default();
//!     let attributes = vec![
//!         ("service.name".to_string(), "prism-node".to_string()),
//!         ("service.version".to_string(), "1.0.0".to_string()),
//!         ("environment".to_string(), "production".to_string()),
//!     ];
//!
//!     // Initialize telemetry system
//!     let telemetry = create_telemetry(&config, attributes)?;
//!
//!     // Your application code here...
//!     tracing::info!("Node started successfully");
//!
//!     // Shutdown telemetry when done
//!     telemetry.shutdown();
//!
//!     Ok(())
//! }
//! ```

mod error;
mod factory;

pub mod metrics_registry;

pub use error::TelemetryError;
pub use factory::{TelemetryInstance, create_telemetry};
