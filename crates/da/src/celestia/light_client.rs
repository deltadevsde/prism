use anyhow::{Result, anyhow};
use async_trait::async_trait;
use celestia_types::nmt::Namespace;
use libp2p::Multiaddr;
use lumina_node::{Node, NodeBuilder};
use prism_events::{EventChannel, EventPublisher, PrismEvent};
use std::{self, str::FromStr, sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock};
use tracing::{trace, warn};

#[cfg(target_arch = "wasm32")]
use lumina_node::{blockstore::IndexedDbBlockstore, store::IndexedDbStore};
use prism_presets::PresetError;
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};
#[cfg(not(target_arch = "wasm32"))]
use {
    blockstore::EitherBlockstore,
    lumina_node::{
        blockstore::{InMemoryBlockstore, RedbBlockstore},
        store::{EitherStore, InMemoryStore, RedbStore},
    },
    redb::Database as RedbDatabase,
    std::{env, path::PathBuf},
    tokio::task::spawn_blocking,
};

use super::CelestiaNetwork;
use crate::{
    FinalizedEpoch, LightDataAvailabilityLayer, VerifiableEpoch,
    celestia::{
        DEFAULT_FETCH_MAX_RETRIES, DEFAULT_FETCH_TIMEOUT, DEFAULT_PRUNING_WINDOW,
        DEVNET_SPECTER_SNARK_NAMESPACE_ID, utils::create_namespace,
    },
    error::DataAvailabilityError,
};
use prism_cross_target::{tasks::TaskManager, token::Token};

#[cfg(target_arch = "wasm32")]
pub type LuminaNode = Node<IndexedDbBlockstore, IndexedDbStore>;

#[cfg(not(target_arch = "wasm32"))]
pub type LuminaNode = Node<
    EitherBlockstore<InMemoryBlockstore, RedbBlockstore>,
    EitherStore<InMemoryStore, RedbStore>,
>;

/// Configuration for Celestia light client data availability layer.
///
/// Light clients provide a resource-efficient way to interact with Celestia
/// without downloading full blocks or maintaining complete chain state. They
/// use data availability sampling and fraud proofs to verify data integrity
/// while minimizing bandwidth and storage requirements.
///
/// ```
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelestiaLightClientDAConfig {
    /// The Celestia network to connect to.
    ///
    /// Must match the network used by other Prism nodes:
    /// - `Arabica`: Development testnet with latest features
    /// - `Mocha`: Stable testnet for production testing
    /// - `Mainnet`: Production network
    ///
    /// Different networks have different block times and fee structures.
    pub celestia_network: CelestiaNetwork,

    /// List of bootnodes to connect to.
    ///
    /// Bootnodes are used to bootstrap the connection to the network.
    /// They are not required for normal operation but can help with initial
    /// connection in case the network is not fully connected or a custom network are used.
    ///
    /// Are the String representations of libp2p multiaddresses on the Celestia network.
    pub bootnodes: Vec<String>,

    /// Hex-encoded namespace ID for SNARK proofs.
    ///
    /// Light clients will only download and verify data from this namespace,
    /// significantly reducing bandwidth usage. Must be exactly 16 hex characters
    /// and match the namespace used by Prism provers.
    ///
    /// Example: "00000000000000de1008"
    pub snark_namespace_id: String,

    /// How long to retain downloaded data before pruning.
    ///
    /// Light clients automatically prune old data to manage storage usage.
    /// This window determines how far back data is kept accessible for queries.
    /// Longer windows provide better availability but use more storage.
    ///
    /// Recommended values:
    /// - Mobile/Browser: 1-3 days
    /// - Desktop: 7-14 days
    /// - Development: 1 day
    #[serde_as(as = "DurationSeconds<u64>")]
    pub pruning_window: Duration,

    /// Timeout for data availability sampling requests.
    ///
    /// Light clients perform sampling to verify data availability without
    /// downloading full blocks. This timeout should account for:
    /// - Network latency to Celestia light nodes
    /// - Time to generate and verify availability proofs
    /// - Potential network congestion
    ///
    /// Recommended: 10-120 seconds depending on network conditions.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub fetch_timeout: Duration,

    /// Maximum retry attempts for failed sampling operations.
    ///
    /// When data availability sampling fails, the client will retry up to
    /// this many times before marking data as unavailable. Higher values
    /// improve reliability but may increase latency during network issues.
    ///
    /// Recommended: 3-5 retries for production, 1-2 for development.
    pub fetch_max_retries: u64,

    /// Storage configuration for downloaded data and metadata.
    ///
    /// Determines where and how the light client stores:
    /// - Downloaded namespace data
    /// - Block headers and availability commitments
    /// - Sampling state and fraud proof caches
    pub store: CelestiaLightClientDAStoreConfig,
}

/// Storage backend configuration for Celestia light client data.
///
/// Light clients need to store downloaded data, block headers, and sampling state
/// to operate efficiently. Different storage backends offer trade-offs between
/// performance, persistence, and platform compatibility.
///
/// # Storage Requirements
///
/// Light clients store:
/// - Downloaded namespace data within the pruning window
/// - Block headers for data availability verification
/// - Sampling proofs and fraud proof caches
/// - Network sync state and peer information
///
/// # Backend Selection Guide
///
/// - **InMemory**: Fastest access, no persistence, limited by RAM
/// - **Disk**: Persistent storage, survives restarts, requires filesystem access
/// - **Browser**: Web-compatible storage using IndexedDB (WASM only)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CelestiaLightClientDAStoreConfig {
    /// In-memory storage for development and testing.
    ///
    /// All data is stored in RAM and lost when the client shuts down.
    /// Provides fastest access times but limited by available memory.
    /// Suitable for:
    /// - Development and testing environments
    /// - Ephemeral deployments where persistence isn't needed
    /// - Performance benchmarking and profiling
    ///
    /// **Limitations:**
    /// - No data persistence across restarts
    /// - Memory usage grows with pruning window size
    /// - Not suitable for long-running production clients
    InMemory,

    /// Persistent disk storage for production deployments.
    ///
    /// Data is stored on the filesystem and survives client restarts.
    /// Provides good performance and supports large datasets that exceed
    /// available RAM.
    ///
    /// **Requirements:**
    /// - Write access to the specified directory path
    /// - Sufficient disk space for the pruning window
    /// - Regular filesystem maintenance and monitoring
    Disk {
        /// Filesystem path for storing light client data.
        ///
        /// This directory will contain:
        /// - Namespace data files organized by block height
        /// - Block header database and indexes
        /// - Sampling state and verification caches
        /// - Client metadata and configuration snapshots
        ///
        /// The path should be:
        /// - Writable by the client process
        /// - On storage with adequate space and performance
        /// - Backed up regularly to prevent data loss
        ///
        /// Example: "/var/lib/prism/celestia-light" or "./data/celestia"
        path: String,
    },

    /// Browser-compatible storage for web applications.
    ///
    /// Uses browser storage APIs like IndexedDB and localStorage to persist
    /// data within the browser environment. Automatically handles storage
    /// quotas and provides fallback mechanisms for different browsers.
    ///
    /// **Browser Compatibility:**
    /// - Modern browsers with IndexedDB support (Chrome, Firefox, Safari, Edge)
    /// - Automatic fallback to localStorage for limited data
    /// - Respects browser storage quotas and eviction policies
    ///
    /// **Limitations:**
    /// - Subject to browser storage limits (typically 50MB-1GB)
    /// - May be cleared by browser cleanup or user action
    /// - Performance varies by browser implementation
    /// - Not suitable for applications requiring guaranteed persistence
    Browser,
}

impl Default for CelestiaLightClientDAConfig {
    fn default() -> Self {
        Self {
            celestia_network: CelestiaNetwork::Arabica,
            snark_namespace_id: "00000000000000de1008".to_string(),
            bootnodes: Vec::new(),
            pruning_window: DEFAULT_PRUNING_WINDOW,
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
            fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES,

            #[cfg(target_arch = "wasm32")]
            store: CelestiaLightClientDAStoreConfig::Browser,
            #[cfg(not(target_arch = "wasm32"))]
            store: CelestiaLightClientDAStoreConfig::Disk {
                path: dirs::home_dir()
                    .or_else(|| env::current_dir().ok())
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".prism/data/light_client/")
                    .to_string_lossy()
                    .into_owned(),
            },
        }
    }
}

impl CelestiaLightClientDAConfig {
    pub fn new_for_specter() -> std::result::Result<Self, PresetError> {
        let mut config = Self::default();
        config.apply_specter_preset()?;
        Ok(config)
    }

    pub fn apply_specter_preset(&mut self) -> std::result::Result<(), PresetError> {
        self.celestia_network = CelestiaNetwork::Mocha;
        self.snark_namespace_id = DEVNET_SPECTER_SNARK_NAMESPACE_ID.to_string();
        Ok(())
    }
}

pub struct LightClientConnection {
    node: Arc<RwLock<Option<LuminaNode>>>,
    event_channel: Arc<EventChannel>,
    snark_namespace: Namespace,
    fetch_timeout: Duration,
    fetch_max_retries: u64,
    config: CelestiaLightClientDAConfig,
    task_manager: TaskManager,
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
        match config {
            CelestiaLightClientDAStoreConfig::InMemory => {
                let blockstore = InMemoryBlockstore::new();
                let store = InMemoryStore::new();
                Ok((EitherBlockstore::Left(blockstore), EitherStore::Left(store)))
            }
            CelestiaLightClientDAStoreConfig::Disk { path } => {
                use std::{fs::create_dir_all, path::Path};

                let base_path = Path::new(&path).to_owned();

                // Ensure directory exists
                if !base_path.exists() {
                    create_dir_all(&base_path).map_err(|e| {
                        DataAvailabilityError::InitializationError(format!(
                            "Failed to create directory {}: {}",
                            base_path.display(),
                            e
                        ))
                    })?;
                }

                let store_path = base_path.join("lumina.redb");
                let db = spawn_blocking(move || RedbDatabase::create(&store_path))
                    .await
                    .map_err(|e| {
                        DataAvailabilityError::InitializationError(format!(
                            "Failed to join blocking task: {}",
                            e
                        ))
                    })?
                    .map_err(|e| {
                        DataAvailabilityError::InitializationError(format!(
                            "Failed to open database at {}: {}",
                            path, e
                        ))
                    })?;
                let db = Arc::new(db);
                let store = RedbStore::new(db.clone()).await.map_err(|e| {
                    DataAvailabilityError::InitializationError(format!(
                        "Failed to create store: {}",
                        e
                    ))
                })?;
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
        Ok(Self {
            node: Arc::new(RwLock::new(None)),
            event_channel: Arc::new(EventChannel::new()),
            snark_namespace: create_namespace(&config.snark_namespace_id)?,
            fetch_timeout: config.fetch_timeout,
            fetch_max_retries: config.fetch_max_retries,
            config: config.clone(),
            task_manager: TaskManager::new(),
        })
    }

    pub fn event_publisher(&self) -> EventPublisher {
        self.event_channel.publisher()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl LightDataAvailabilityLayer for LightClientConnection {
    async fn start(&self) -> Result<(), DataAvailabilityError> {
        // Check if already started and claim the slot atomically
        let mut node_guard = self.node.write().await;
        if node_guard.is_some() {
            return Ok(()); // Already started
        }

        let (blockstore, store) = Self::setup_stores(&self.config.store).await?;

        let mut node = NodeBuilder::new()
            .network(self.config.celestia_network.clone())
            .store(store)
            .blockstore(blockstore)
            .pruning_window(self.config.pruning_window);

        if !self.config.bootnodes.is_empty() {
            let multiaddrs: Vec<Multiaddr> = self
                .config
                .bootnodes
                .clone()
                .into_iter()
                .filter_map(|addr| Multiaddr::from_str(&addr).ok())
                .collect();

            if multiaddrs.len() != self.config.bootnodes.len() {
                warn!(
                    "Some bootnodes failed to parse to libp2p multiaddrs. Valid addresses contain: {:#?}",
                    multiaddrs
                );
            }

            node = node.bootnodes(multiaddrs);
        }

        let (node, event_subscriber) = node
            .start_subscribed()
            .await
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))?;

        let lumina_sub = Arc::new(Mutex::new(event_subscriber));

        // Start forwarding lumina events to our existing event channel
        let event_channel = self.event_channel.clone();
        self.task_manager
            .spawn(move |token| forward_lumina_events(event_channel.publisher(), lumina_sub, token))
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))?;

        // Store the node
        *node_guard = Some(node);

        Ok(())
    }

    async fn stop(&self) -> Result<(), DataAvailabilityError> {
        {
            let mut node_guard = self.node.write().await;
            if let Some(node) = node_guard.take() {
                // Joining is handled internally within lumina node
                // This will also stop the forwarding task, because we are closing the sender
                node.stop().await;
            }
        }

        // Stop all managed tasks
        self.task_manager
            .stop()
            .await
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))?;

        Ok(())
    }

    async fn get_finalized_epochs(&self, height: u64) -> Result<Vec<VerifiableEpoch>> {
        trace!(
            "searching for epoch on da layer at height {} under namespace",
            height
        );
        let node_guard = self.node.read().await;
        let node = match node_guard.as_ref() {
            Some(n) => n,
            None => return Err(anyhow!("Light client not started. Call start() first.")),
        };

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

    fn event_channel(&self) -> Arc<EventChannel> {
        self.event_channel.clone()
    }
}

/// Starts forwarding events from a Lumina event subscriber to the event channel.
/// Returns a future that runs until the cancellation token is triggered.
async fn forward_lumina_events(
    publisher: EventPublisher,
    lumina_sub: Arc<Mutex<lumina_node::events::EventSubscriber>>,
    token: Token,
) {
    loop {
        tokio::select! {
            _ = token.triggered() => {
                break;
            }
            event_result = async {
                let mut subscriber = lumina_sub.lock().await;
                subscriber.recv().await
            } => {
                match event_result {
                    Ok(event) => {
                        if let lumina_node::events::NodeEvent::AddedHeaderFromHeaderSub { height } =
                            event.event
                        {
                            publisher.send(PrismEvent::UpdateDAHeight { height });
                        } else {
                            #[cfg(target_arch = "wasm32")]
                            publisher.send(PrismEvent::LuminaEvent { event: event.event });

                            #[cfg(not(target_arch = "wasm32"))]
                            trace!("lumina event: {:?}", event);
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}
