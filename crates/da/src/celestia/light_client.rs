#[cfg(feature = "uniffi")]
use crate::celestia::utils::NetworkConfig;
use crate::{
    FinalizedEpoch, LightDataAvailabilityLayer, VerifiableEpoch,
    celestia::{
        DEFAULT_FETCH_MAX_RETRIES, DEFAULT_FETCH_TIMEOUT, DEFAULT_PRUNING_DELAY,
        DEFAULT_SAMPLING_WINDOW, utils::create_namespace,
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
use serde::{Deserialize, Serialize};
use std::{self, sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, trace, warn};

#[cfg(target_arch = "wasm32")]
use lumina_node::{blockstore::IndexedDbBlockstore, store::IndexedDbStore};

use lumina_node::NodeBuilder;

#[cfg(not(target_arch = "wasm32"))]
use {blockstore::EitherBlockstore, redb::Database, tokio::task::spawn_blocking};

#[cfg(feature = "uniffi")]
use lumina_node_uniffi::types::NodeConfig as CelestiaNodeConfig;

#[cfg(not(target_arch = "wasm32"))]
use lumina_node::{blockstore::RedbBlockstore, store::RedbStore};

#[cfg(target_arch = "wasm32")]
pub type LuminaNode = Node<IndexedDbBlockstore, IndexedDbStore>;

#[cfg(not(target_arch = "wasm32"))]
pub type LuminaNode = Node<
    EitherBlockstore<InMemoryBlockstore, RedbBlockstore>,
    EitherStore<InMemoryStore, RedbStore>,
>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelestiaLightClientDAConfig {
    pub celestia_network: CelestiaNetwork,
    pub snark_namespace_id: String,
    pub sampling_window: Duration,
    pub pruning_delay: Duration,
    pub fetch_timeout: Duration,
    pub fetch_max_retries: u64,
}

impl Default for CelestiaLightClientDAConfig {
    fn default() -> Self {
        Self {
            celestia_network: CelestiaNetwork::Arabica, // Default to Arabica network
            snark_namespace_id: "00000000000000de1008".to_string(),
            sampling_window: DEFAULT_SAMPLING_WINDOW, // Default to 5 minutes
            pruning_delay: DEFAULT_PRUNING_DELAY,     // Default to 7 days
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,     // Default to 1 minute
            fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES, // Default to 5 retries
        }
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
    async fn setup_stores() -> Result<
        (
            EitherBlockstore<InMemoryBlockstore, RedbBlockstore>,
            EitherStore<InMemoryStore, RedbStore>,
        ),
        DataAvailabilityError,
    > {
        let db = spawn_blocking(|| Database::create("lumina.redb"))
            .await
            .expect("Failed to join")
            .expect("Failed to open the database");
        let db = Arc::new(db);

        let store = RedbStore::new(db.clone()).await.expect("Failed to create a store");
        let blockstore = RedbBlockstore::new(db);

        let either_blockstore = EitherBlockstore::Right(blockstore);
        let either_store = EitherStore::Right(store);

        Ok((either_blockstore, either_store))
    }

    #[cfg(target_arch = "wasm32")]
    async fn setup_stores() -> Result<(IndexedDbBlockstore, IndexedDbStore), DataAvailabilityError>
    {
        let store = IndexedDbStore::new("prism-store")
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create IndexedDbStore: {}", e))?;

        let blockstore = IndexedDbBlockstore::new("prism-blockstore")
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create IndexedDbBlockstore: {}", e))?;

        Ok((blockstore, store))
    }

    pub async fn new(config: &CelestiaLightClientDAConfig) -> Result<Self, DataAvailabilityError> {
        #[cfg(target_arch = "wasm32")]
        let (blockstore, store) = Self::setup_stores().await.unwrap();
        #[cfg(not(target_arch = "wasm32"))]
        let (blockstore, store) = Self::setup_stores().await?;

        let (node, event_subscriber) = NodeBuilder::new()
            .network(config.celestia_network.clone())
            .store(store)
            .blockstore(blockstore)
            .pruning_delay(config.pruning_delay)
            .sampling_window(config.sampling_window)
            .start_subscribed()
            .await
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))?;

        let lumina_sub = Arc::new(Mutex::new(event_subscriber));

        // Creates an EventChannel that starts forwarding lumina events to the subscriber
        let prism_chan = EventChannel::from(lumina_sub.clone());

        let snark_namespace = create_namespace(&config.snark_namespace_id)?;

        Ok(LightClientConnection {
            node: Arc::new(RwLock::new(node)),
            event_channel: Arc::new(prism_chan),
            snark_namespace,
            fetch_timeout: config.fetch_timeout,
            fetch_max_retries: config.fetch_max_retries,
        })
    }

    #[cfg(feature = "uniffi")]
    pub async fn new_with_config(
        config: &NetworkConfig,
        node_config: Option<CelestiaNodeConfig>,
    ) -> Result<Self> {
        #[cfg(target_arch = "wasm32")]
        let bootnodes = resolve_bootnodes(&bootnodes).await?;

        #[cfg(target_arch = "wasm32")]
        let (blockstore, store) = Self::setup_stores().await.unwrap();

        let celestia_config = config
            .celestia_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Celestia config is required but not provided"))?;

        let node_builder = node_config
            .ok_or_else(|| anyhow::anyhow!("Node config is required for uniffi but not provided"))?
            .into_node_builder()
            .await?;
        let (node, event_subscriber) = node_builder.start_subscribed().await?;

        let lumina_sub = Arc::new(Mutex::new(event_subscriber));

        // Creates an EventChannel that starts forwarding lumina events to the subscriber
        let prism_chan = EventChannel::from(lumina_sub.clone());

        let snark_namespace = create_namespace(&celestia_config.snark_namespace_id)?;

        Ok(LightClientConnection {
            node: Arc::new(RwLock::new(node)),
            event_channel: Arc::new(prism_chan),
            snark_namespace,
            fetch_timeout: celestia_config.fetch_timeout,
            fetch_max_retries: celestia_config.fetch_max_retries,
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
        let header = match node.get_header_by_height(height).await {
            Ok(h) => h,
            Err(NodeError::Store(StoreError::NotFound)) => {
                debug!(
                    "header for height {} not found locally, fetching from network",
                    height
                );
                node.request_header_by_height(height).await?
            }
            Err(e) => return Err(anyhow!("Failed to fetch header: {}", e)),
        };

        for attempt in 0..self.fetch_max_retries {
            match node
                .request_all_blobs(&header, self.snark_namespace, Some(self.fetch_timeout))
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
