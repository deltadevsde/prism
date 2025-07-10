//! Native library providing Rust to mobile language bindings for the Prism Lightclient.
//!
//! This crate uses Mozilla's UniFFI to generate Swift and Kotlin bindings for the Prism
//! lightclient, allowing it to be used from iOS and Android applications.
mod error;
mod types;

use error::{LightClientError, Result};
use prism_da::celestia::{light_client::LightClientConnection, utils::Network};

use prism_events::EventSubscriber;
use prism_lightclient::LightClient as CoreLightClient;
use std::{str::FromStr, sync::Arc};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use types::UniffiLightClientEvent;
use uniffi::Object;

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
    pub async fn new(network_name: String, base_path: String) -> Result<Self> {
        let network = Network::from_str(&network_name)
            .map_err(|e| LightClientError::network_error(format!("Invalid network: {}", e)))?;
        let network_config = network.config();

        let node_config = lumina_node_uniffi::types::NodeConfig {
            base_path: Some(base_path),
            network: network_config.celestia_network.clone(),
            bootnodes: None,
            pruning_delay_secs: None,
            batch_size: None,
            ed25519_secret_key_bytes: None,
            syncing_window_secs: None,
        };

        // Initialize connection
        let da = LightClientConnection::new_with_config(&network_config, Some(node_config))
            .await
            .map_err(|e| {
            LightClientError::network_error(format!("Failed to connect to light client: {}", e))
        })?;

        let event_sub = da.event_channel.subscribe();

        let inner = Arc::new(CoreLightClient::new(
            Arc::new(da),
            network_config.verifying_key,
            CancellationToken::new(),
        ));

        Ok(Self {
            inner,
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
