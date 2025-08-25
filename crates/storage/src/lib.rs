#![feature(coverage_attribute)]
//! # Prism Storage Layer
//!
//! This crate provides database abstraction and implementations for persistent storage
//! in the Prism key transparency network. It supports multiple storage backends
//! optimized for different use cases and deployment environments.
//!
//! ## Overview
//!
//! The storage layer is responsible for:
//! - Persisting the key directory tree state and merkle proofs
//! - Storing transaction batches and processing status
//! - Maintaining DA layer synchronization metadata
//! - Providing atomic operations and consistent snapshots
//!
//! ## Supported Backends
//!
//! ### RocksDB
//! - Production-ready embedded database with LSM-tree architecture
//! - Optimized for write-heavy workloads with efficient compaction
//! - ACID compliance with atomic batch writes
//! - Configurable compression and caching
//!
//! ### InMemory
//! - Hash map-based storage for testing and development
//! - Fast access with no disk I/O overhead
//! - No persistence across process restarts
//! - Suitable for CI/CD and local development
//!
//! ## Performance Considerations
//!
//! ### RocksDB Optimization
//!
//! - Use appropriate hardware (fast SSDs recommended)
//! - Configure adequate system memory for caching
//! - Monitor disk space for compaction operations
//! - Consider write buffer size based on workload
//!
//! ### InMemory Limitations
//!
//! - Memory usage grows with stored data
//! - No persistence across restarts
//! - May not be suitable for large datasets
//! - Consider memory limits in containerized environments
//!
//! ## Quick Start
//!
//! ### Basic Usage
//!
//! ```rust
//! use prism_storage::{DatabaseConfig, create_storage};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Create an in-memory database for development
//!     let config = DatabaseConfig::InMemory;
//!     let db = create_storage(&config).await?;
//!
//!     // Database is ready for use
//!     println!("Database initialized successfully");
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Production Setup with RocksDB
//!
//! ```rust,no_run
//! use prism_storage::{DatabaseConfig, create_storage, rocksdb::RocksDBConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Configure persistent storage
//!     let config = DatabaseConfig::RocksDB(RocksDBConfig {
//!         path: "/var/lib/prism/database".to_string(),
//!     });
//!
//!     let db = create_storage(&config).await?;
//!
//!     // Database will persist data across restarts
//!     println!("Persistent database ready at /var/lib/prism/database");
//!
//!     Ok(())
//! }
//! ```

mod database;
mod factory;
pub mod inmemory;
pub mod rocksdb;

#[cfg(test)]
mod tests;

pub use crate::{
    database::Database,
    factory::{DatabaseConfig, create_storage},
};
