use crate::{
    FinalizedEpoch, LightDataAvailabilityLayer, VerifiableEpoch,
    celestia::{
        DEFAULT_FETCH_MAX_RETRIES, DEFAULT_FETCH_TIMEOUT, DEFAULT_PRUNING_WINDOW,
        DEVNET_SPECTER_SNARK_NAMESPACE_ID, utils::create_namespace,
    },
};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use celestia_types::nmt::Namespace;
#[cfg(not(target_arch = "wasm32"))]
use lumina_node::blockstore::InMemoryBlockstore;
#[cfg(not(target_arch = "wasm32"))]
use lumina_node::store::{EitherStore, InMemoryStore};
use lumina_node::{Node, NodeError, network::Network as CelestiaNetwork, store::StoreError};
use prism_errors::DataAvailabilityError;
use prism_events::{EventChannel, EventPublisher};
use prism_presets::{ApplyPreset, LightClientPreset, PresetError};
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};
use std::{self, env::current_dir, sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, trace, warn};

#[cfg(target_arch = "wasm32")]
use lumina_node::{blockstore::IndexedDbBlockstore, store::IndexedDbStore};

use lumina_node::NodeBuilder;

#[cfg(not(target_arch = "wasm32"))]
use {blockstore::EitherBlockstore, redb::Database as RedbDatabase, tokio::task::spawn_blocking};

#[cfg(not(target_arch = "wasm32"))]
use lumina_node::{blockstore::RedbBlockstore, store::RedbStore};

#[cfg(target_arch = "wasm32")]
pub type LuminaNode = Node<IndexedDbBlockstore, IndexedDbStore>;

#[cfg(not(target_arch = "wasm32"))]
pub type LuminaNode = Node<
    EitherBlockstore<InMemoryBlockstore, RedbBlockstore>,
    EitherStore<InMemoryStore, RedbStore>,
>;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelestiaLightClientDAConfig {
    pub celestia_network: CelestiaNetwork,
    pub snark_namespace_id: String,
    #[serde_as(as = "DurationSeconds<u64>")]
    pub pruning_window: Duration,
    #[serde_as(as = "DurationSeconds<u64>")]
    pub fetch_timeout: Duration,
    pub fetch_max_retries: u64,
    pub store: CelestiaLightClientDAStoreConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CelestiaLightClientDAStoreConfig {
    InMemory,
    Disk { path: String },
    Browser,
}

impl Default for CelestiaLightClientDAConfig {
    fn default() -> Self {
        Self {
            celestia_network: CelestiaNetwork::Arabica, // Default to Arabica network
            snark_namespace_id: "00000000000000de1008".to_string(),
            pruning_window: DEFAULT_PRUNING_WINDOW, // Default to 7 days
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,   // Default to 1 minute
            fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES, // Default to 5 retries

            #[cfg(target_arch = "wasm32")]
            store: CelestiaLightClientDAStoreConfig::Browser,
            #[cfg(not(target_arch = "wasm32"))]
            store: CelestiaLightClientDAStoreConfig::Disk {
                path: dirs::home_dir()
                    .unwrap_or_else(|| current_dir().unwrap_or_default())
                    .join(".prism/data/light_client/")
                    .to_string_lossy()
                    .into_owned(),
            },
        }
    }
}

impl ApplyPreset<LightClientPreset> for CelestiaLightClientDAConfig {
    fn apply_preset(&mut self, preset: &LightClientPreset) -> Result<(), PresetError> {
        match preset {
            LightClientPreset::Specter => {
                self.celestia_network = CelestiaNetwork::Mocha;
                self.snark_namespace_id = DEVNET_SPECTER_SNARK_NAMESPACE_ID.to_string();
            }
        }
        Ok(())
    }
}

pub struct LightClientConnection {
    pub node: Arc<RwLock<LuminaNode>>,
    pub event_channel: Arc<EventChannel>,
    pub snark_namespace: Namespace,
    pub fetch_timeout: Duration,
    pub fetch_max_retries: u64,
}

impl LightClientConnection {
    #[cfg(not(target_arch = "wasm32"))]
    async fn setup_stores(
        config: &CelestiaLightClientDAStoreConfig,
    ) -> Result<
        (
            EitherBlockstore<InMemoryBlockstore, RedbBlockstore>,
            EitherStore<InMemoryStore, RedbStore>,
        ),
        DataAvailabilityError,
    > {
        use std::path::Path;

        match config {
            CelestiaLightClientDAStoreConfig::InMemory => {
                let blockstore = InMemoryBlockstore::new();
                let store = InMemoryStore::new();

                Ok((EitherBlockstore::Left(blockstore), EitherStore::Left(store)))
            }
            CelestiaLightClientDAStoreConfig::Disk { path } => {
                let base_path = Path::new(&path).to_owned();
                let store_path = base_path.join("lumina.redb");

                let db = spawn_blocking(move || RedbDatabase::create(&store_path))
                    .await
                    .expect("Failed to join")
                    .expect("Failed to open the database");
                let db = Arc::new(db);

                let store = RedbStore::new(db.clone()).await.expect("Failed to create a store");
                let blockstore = RedbBlockstore::new(db);

                Ok((
                    EitherBlockstore::Right(blockstore),
                    EitherStore::Right(store),
                ))
            }
            CelestiaLightClientDAStoreConfig::Browser => {
                Err(DataAvailabilityError::InitializationError(
                    "browser store type can only be used with wasm".to_string(),
                ))
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn setup_stores(
        config: &CelestiaLightClientDAStoreConfig,
    ) -> Result<(IndexedDbBlockstore, IndexedDbStore), DataAvailabilityError> {
        if !matches!(config, CelestiaLightClientDAStoreConfig::Browser) {
            return Err(DataAvailabilityError::InitializationError(
                "wasm DA can only use browser store type".to_string(),
            ));
        }

        let store = IndexedDbStore::new("prism-store").await.map_err(|e| {
            DataAvailabilityError::InitializationError(format!(
                "Failed to create IndexedDbStore: {}",
                e
            ))
        })?;

        let blockstore = IndexedDbBlockstore::new("prism-blockstore").await.map_err(|e| {
            DataAvailabilityError::InitializationError(format!(
                "Failed to create IndexedDbBlockstore: {}",
                e
            ))
        })?;

        Ok((blockstore, store))
    }

    pub async fn new(config: &CelestiaLightClientDAConfig) -> Result<Self, DataAvailabilityError> {
        // #[cfg(target_arch = "wasm32")]
        // let (blockstore, store) = Self::setup_stores(&config.store).await?;
        // #[cfg(not(target_arch = "wasm32"))]
        let (blockstore, store) = Self::setup_stores(&config.store).await?;

        let (node, event_subscriber) = NodeBuilder::new()
            .network(config.celestia_network.clone())
            .store(store)
            .blockstore(blockstore)
            .pruning_window(config.pruning_window)
            .start_subscribed()
            .await
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))?;

        let lumina_sub = Arc::new(Mutex::new(event_subscriber));

        // Creates an EventChannel that starts forwarding lumina events to the subscriber
        let prism_chan = EventChannel::from(lumina_sub.clone());

        Ok(LightClientConnection {
            node: Arc::new(RwLock::new(node)),
            event_channel: Arc::new(prism_chan),
            snark_namespace: create_namespace(&config.snark_namespace_id)?,
            fetch_timeout: config.fetch_timeout,
            fetch_max_retries: config.fetch_max_retries,
        })
    }

    pub fn event_publisher(&self) -> EventPublisher {
        self.event_channel.publisher()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl LightDataAvailabilityLayer for LightClientConnection {
    fn event_channel(&self) -> Arc<EventChannel> {
        self.event_channel.clone()
    }

    async fn get_finalized_epochs(&self, height: u64) -> Result<Vec<VerifiableEpoch>> {
        trace!(
            "searching for epoch on da layer at height {} under namespace",
            height
        );
        let node = self.node.read().await;

        for attempt in 0..self.fetch_max_retries {
            match node
                .request_all_blobs(self.snark_namespace, height, Some(self.fetch_timeout))
                .await
            {
                Ok(blobs) => {
                    let epochs: Vec<VerifiableEpoch> = blobs
                        .into_iter()
                        .filter_map(|blob| match FinalizedEpoch::try_from(&blob) {
                            Ok(epoch) => Some(Box::new(epoch) as VerifiableEpoch),
                            Err(_) => {
                                warn!(
                                    "marshalling blob from height {} to epoch json: {:?}",
                                    height, &blob
                                );
                                None
                            }
                        })
                        .collect();
                    return Ok(epochs);
                }
                Err(e) => {
                    warn!(
                        "failed to fetch data on attempt {} with error: {}.",
                        attempt, e
                    );
                }
            }
        }
        return Err(anyhow!(DataAvailabilityError::DataRetrievalError(
            height,
            "Max retry count exceeded".to_string()
        )));
    }
}
