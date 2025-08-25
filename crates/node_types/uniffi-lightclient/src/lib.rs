//! Native library providing Rust to mobile language bindings for the Prism Lightclient.
//!
//! This crate uses Mozilla's UniFFI to generate Swift and Kotlin bindings for the Prism
//! lightclient, allowing it to be used from iOS and Android applications.
mod config;
mod error;
mod types;

use error::{LightClientError, Result};
use prism_da::create_light_client_da_layer;

use prism_events::EventSubscriber;
use prism_lightclient::{LightClient as CoreLightClient, create_light_client};
use prism_presets::{ApplyPreset, LightClientPreset};
use std::{str::FromStr, sync::Arc};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use types::UniffiLightClientEvent;
use uniffi::Object;

use crate::config::UniffiLightClientConfig;

uniffi::setup_scaffolding!();

/// The Prism Lightclient manages the connection to the Celestia network and verifies epoch data.
#[derive(Object)]
pub struct LightClient {
    inner: Arc<CoreLightClient>,
    event_subscriber: Mutex<EventSubscriber>,
}

#[uniffi::export(async_runtime = "tokio")]
impl LightClient {
    /// Creates a new Lightclient for the specified network.
    #[uniffi::constructor]
    pub async fn new(network_name: String, base_path: Option<String>) -> Result<Self> {
        let preset = LightClientPreset::from_str(&network_name).map_err(|e| {
            LightClientError::initialization_error(format!("Parsing preset failed: {}", e))
        })?;

        let mut config = UniffiLightClientConfig::default_with_preset(&preset).map_err(|e| {
            LightClientError::initialization_error(format!("Loading config failed: {}", e))
        })?;

        config.da.use_storage_path(base_path).map_err(|e| {
            LightClientError::initialization_error(format!("Adjusting path failed: {}", e))
        })?;

        let da = create_light_client_da_layer(&config.da).await.map_err(|e| {
            LightClientError::initialization_error(format!(
                "Failed to create light client DA: {}",
                e
            ))
        })?;

        let event_sub = da.event_channel().subscribe();

        let light_client = create_light_client(da, &config.light_client, CancellationToken::new())
            .map_err(|e| {
                LightClientError::initialization_error(format!(
                    "Failed to create light client: {}",
                    e
                ))
            })?;

        Ok(Self {
            inner: Arc::new(light_client),
            event_subscriber: Mutex::new(event_sub),
        })
    }

    /// Starts the lightclient and begins syncing with the network.
    pub async fn start(&self) -> Result<()> {
        let inner_clone = self.inner.clone();
        inner_clone.run().await.map_err(|e| LightClientError::general_error(e.to_string()))
    }

    /// Gets the current commitment.
    pub async fn get_current_commitment(&self) -> Result<Option<String>> {
        match self.inner.get_latest_commitment().await {
            Some(commitment) => Ok(Some(commitment.to_string())),
            None => Ok(None),
        }
    }

    /// Returns the next event from the lightclient's event channel.
    pub async fn next_event(&self) -> Result<UniffiLightClientEvent> {
        let mut event_subscriber = self.event_subscriber.lock().await;
        let event_info = event_subscriber
            .recv()
            .await
            .map_err(|_| LightClientError::event_error("Event channel closed"))?;

        Ok(event_info.event.into())
    }
}
