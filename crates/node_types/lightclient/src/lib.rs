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
//!     // Provide a DA layer instance that can be used by the light client
//!     let da_config = LightClientDAConfig::InMemory;
//!     let da = create_light_client_da_layer(&da_config).await?;
//!
//!     // Set light client configuration parameters
//!     let lc_config = LightClientConfig {
//!         verifying_key_str: "der_base64_encoded_verifying_key_here".to_string(),
//!     };
//!     let cancellation_token = CancellationToken::new();
//!
//!     // Create and run the light client
//!     let light_client = create_light_client(da.clone(), &lc_config, cancellation_token.clone())?;
//!     let light_client = Arc::new(light_client);
//!
//!     // Start the light client (this will run until cancelled)
//!     let lc_handle = tokio::spawn({
//!         let light_client = light_client.clone();
//!         async move { light_client.run().await }
//!     });
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
//!     cancellation_token.cancel();
//!     lc_handle.await??;
//!
//!     Ok(())
//! }
//! ```

#![feature(future_join)]

pub mod lightclient;
pub use lightclient::LightClient;
mod factory;

#[cfg(test)]
mod tests;

pub use factory::*;
