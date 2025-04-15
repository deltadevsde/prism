//! Native library providing Rust to mobile language bindings for the Prism Lightclient.
//!
//! This crate uses Mozilla's UniFFI to generate Swift and Kotlin bindings for the Prism lightclient,
//! allowing it to be used from iOS and Android applications.

mod error;
mod types;

use error::{LightClientError, Result};
use prism_da::celestia::{light_client::LightClientConnection, utils::Network};
use prism_lightclient::{
    LightClient as CoreLightClient,
    events::{EventChannel, EventSubscriber},
};
use std::{str::FromStr, sync::Arc};
use tokio::{
    runtime::Runtime,
    sync::{Mutex, RwLock},
};
use types::UniffiLightClientEvent;
use uniffi::Object;

uniffi::setup_scaffolding!();

/// The Prism Lightclient manages the connection to the Celestia network and verifies epoch data.
#[derive(Object)]
pub struct LightClient {
    inner: Arc<CoreLightClient>,
    runtime: RwLock<Runtime>,
    event_subscriber: Mutex<Option<EventSubscriber>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl LightClient {
    /// Creates a new Lightclient for the specified network.
    #[uniffi::constructor]
    pub fn new(
        network_name: String,
        start_height: u64,
        verifying_key_bytes: Option<Vec<u8>>,
        base_path: String,
    ) -> Result<Self> {
        let runtime = Runtime::new().map_err(|e| {
            LightClientError::initialization_error(format!("Failed to create runtime: {}", e))
        })?;

        let network = Network::from_str(&network_name)
            .map_err(|e| LightClientError::network_error(format!("Invalid network: {}", e)))?;
        let network_config = network.config();

        let da = runtime.block_on(async {
            let node_config = lumina_node_uniffi::types::NodeConfig {
                base_path: Some(base_path),
                network: network_config.celestia_network.clone(),
                bootnodes: None,
                pruning_delay_secs: None,
                batch_size: None,
                ed25519_secret_key_bytes: None,
                syncing_window_secs: None,
            };

            LightClientConnection::new(&network_config, Some(node_config)).await.map_err(|e| {
                LightClientError::network_error(format!("Failed to connect to light client: {}", e))
            })
        })?;

        // todo: start height still relevant? No, after rebase not anymore
        let start_height = network_config
            .celestia_config
            .as_ref()
            .map(|cfg| cfg.start_height)
            .unwrap_or(start_height);

        let verifying_key = if let Some(key_bytes) = verifying_key_bytes {
            // todo
            None
        } else {
            network_config.verifying_key
        };

        let event_channel = EventChannel::new();
        let event_publisher = event_channel.publisher();
        let event_subscriber = event_channel.subscribe();

        let inner = Arc::new(CoreLightClient::new(
            Arc::new(da),
            start_height,
            verifying_key,
            event_publisher,
        ));

        Ok(Self {
            inner,
            runtime: RwLock::new(runtime),
            event_subscriber: Mutex::new(Some(event_subscriber)),
        })
    }

    /// Gets the current commitment (Merkle root) of the network.
    pub async fn get_current_commitment(&self) -> Result<Option<String>> {
        match self.inner.get_latest_commitment().await {
            Some(commitment) => Ok(Some(commitment.to_string())),
            None => Ok(None),
        }
    }

    /// Returns the next event from the lightclient's event channel.
    pub async fn next_event(&self) -> Result<UniffiLightClientEvent> {
        let mut event_subscriber = self.event_subscriber.lock().await;
        match event_subscriber.as_mut() {
            Some(subscriber) => {
                let event_info = subscriber
                    .recv()
                    .await
                    .map_err(|_| LightClientError::event_error("Event channel closed"))?;

                Ok(event_info.event.into())
            }
            None => Err(LightClientError::event_error(
                "Event subscriber not initialized",
            )),
        }
    }
}
