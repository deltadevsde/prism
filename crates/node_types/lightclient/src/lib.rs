#![feature(coverage_attribute)]
//! # Prism Light Client
//!
//! A lightweight client implementation for the Prism key transparency network that provides
//! efficient verification of key directory operations without maintaining full state.
//!
//! ## Overview
//!
//! Light clients offer a resource-efficient way to participate in the Prism network by:
//! - Verifying SNARK proofs cryptographically rather than re-executing operations
//! - Maintaining minimal state (only the latest commitment)
//! - Relying on the data availability layer for epoch data
//! - Supporting both forward and backward synchronization
//!
//! ## Security Model
//!
//! Light clients assume:
//! - At least one honest full node exists in the network
//! - The configured verifying key corresponds to a trusted prover
//! - The DA layer provides data availability guarantees
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio_util::sync::CancellationToken;
//! use prism_da::{LightClientDAConfig, create_light_client_da_layer};
//! use prism_events::PrismEvent;
//! use prism_lightclient::{LightClientConfig, create_light_client};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Set light client configuration parameters
//!     let lc_config = LightClientConfig {
//!         da: LightClientDAConfig::InMemory,
//!         verifying_key_str: "der_base64_encoded_verifying_key_or_path_here".to_string(),
//!         allow_mock_proofs: true,
//!     };
//!
//!     // Create and run the light client
//!     let light_client = create_light_client(&lc_config).await?;
//!     light_client.start().await?;
//!
//!     // Query the latest commitment
//!     if let Some(commitment) = light_client.get_latest_commitment().await {
//!         println!("Latest commitment: {:?}", commitment);
//!     }
//!
//!     // Get sync status
//!     let sync_state = light_client.get_sync_state().await;
//!     println!("Current DA height: {}", sync_state.current_height);
//!
//!     // Shutdown gracefully
//!     light_client.stop().await?;
//!
//!     Ok(())
//! }
//! ```

#![feature(future_join)]

mod factory;
pub mod lightclient;
mod syncer;

pub use factory::*;
pub use lightclient::LightClient;
pub use syncer::SyncState;

#[cfg(test)]
mod tests;
