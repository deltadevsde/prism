#![feature(coverage_attribute)]
//! # Prism Prover Node
//!
//! A full-featured Prism node implementation that can operate as either a proof-generating
//! prover or a validating full node, providing complete network participation capabilities.
//!
//! ## Overview
//!
//! The prover crate implements the core logic for maintaining Prism's key directory state,
//! processing transactions, and generating SNARK proofs. It serves as both the authoritative
//! state keeper and the proof generator for the network.
//!
//! ## Key Features
//!
//! - **Complete State Management**: Maintains the full key directory tree
//! - **Transaction Processing**: Batches and processes incoming transactions
//! - **SNARK Proof Generation**: Creates cryptographic proofs using SP1 zkVM
//! - **DA Layer Integration**: Publishes epochs and synchronizes state
//! - **REST API Server**: Provides HTTP endpoints for client interactions
//! - **Flexible Operation Modes**: Can run as prover or full node
//!
//! ## Performance Considerations
//!
//! ### Resource Requirements
//!
//! - **CPU**: Multi-core processor for parallel proof generation
//! - **Memory**: 8GB+ RAM for proof workspace and tree state
//! - **Storage**: Fast SSD for database operations (RocksDB recommended)
//! - **Network**: Stable connection to DA layer with low latency
//!
//! ### Optimization Tips
//!
//! - Use `recursive_proofs: false` for development to speed up proof generation
//! - Adjust `max_epochless_gap` based on transaction volume and finality requirements
//! - Use RocksDB with appropriate configuration for production workloads
//! - Monitor memory usage during proof generation peaks
//!
//! ## Quick Start
//!
//! ### Running a Prover
//!
//! ```rust,no_run
//! use prism_prover::{ProverConfig, WebServerConfig, create_prover_as_prover};
//! use prism_storage::{DatabaseConfig, create_storage};
//! use prism_da::{FullNodeDAConfig, create_full_node_da_layer};
//! use tokio_util::sync::CancellationToken;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Initialize storage
//!     let db_config = DatabaseConfig::InMemory;
//!     let db = create_storage(&db_config).await?;
//!
//!     // Initialize DA layer
//!     let da_config = FullNodeDAConfig::InMemory;
//!     let da = create_full_node_da_layer(&da_config).await?;
//!
//!     // Configure the prover
//!     let prover_config = ProverConfig {
//!         signing_key_path: "/secure/keys/prover.p8".to_string(),
//!         start_height: 1,
//!         max_epochless_gap: 1000,        // Less frequent proofs
//!         recursive_proofs: true,         // Production mode
//!         webserver: WebServerConfig {
//!             enabled: true,
//!             host: "0.0.0.0".to_string(), // Bind to all interfaces
//!             port: 41997,
//!         },
//!     };
//!
//!     // Create and start the prover
//!     let cancellation_token = CancellationToken::new();
//!     let prover = create_prover_as_prover(
//!         &prover_config,
//!         db,
//!         da,
//!         cancellation_token.clone()
//!     )?;
//!
//!     let prover = Arc::new(prover);
//!
//!     // Start the prover (this runs until cancelled)
//!     let prover_handle = tokio::spawn({
//!         let prover = prover.clone();
//!         async move { prover.run().await }
//!     });
//!
//!     // Prover is now running and accepting transactions...
//!     println!("Prover started on port {}", prover_config.webserver.port);
//!
//!     // Graceful shutdown
//!     cancellation_token.cancel();
//!     prover_handle.await??;
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Running a Full Node (Non-Proving)
//!
//! ```rust,no_run
//! use prism_prover::{FullNodeConfig, create_prover_as_full_node};
//! use prism_storage::{DatabaseConfig, create_storage};
//! use prism_da::{FullNodeDAConfig, create_full_node_da_layer};
//! use tokio_util::sync::CancellationToken;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let db = create_storage(&DatabaseConfig::InMemory).await?;
//!     let da = create_full_node_da_layer(&FullNodeDAConfig::InMemory).await?;
//!
//!     let config = FullNodeConfig::default();
//!     let cancellation_token = CancellationToken::new();
//!
//!     let full_node = create_prover_as_full_node(&config, db, da, cancellation_token)?;
//!     let full_node = Arc::new(full_node);
//!
//!     // Full node validates state but doesn't generate proofs
//!     let handle = tokio::spawn({
//!         let full_node = full_node.clone();
//!         async move { full_node.run().await }
//!     });
//!
//!     println!("Full node started on port {}", config.webserver.port);
//!
//!     handle.await??;
//!     Ok(())
//! }
//! ```

mod factory;
mod prover;
mod prover_engine;
mod sequencer;
mod syncer;
mod tx_buffer;
mod webserver;

pub use factory::*;
pub use prover::{Prover, ProverEngineOptions, ProverOptions, SequencerOptions, SyncerOptions};
pub use webserver::{WebServer, WebServerConfig};

#[macro_use]
extern crate tracing;
