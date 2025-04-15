use super::utils::{NetworkConfig, create_namespace};
use crate::{FinalizedEpoch, LightDataAvailabilityLayer};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use blockstore::EitherBlockstore;
use celestia_types::nmt::Namespace;
use log::trace;
use lumina_node::{
    Node,
    blockstore::InMemoryBlockstore,
    events::EventSubscriber,
    store::{EitherStore, InMemoryStore},
};
use lumina_node_uniffi::types::NodeConfig;
use prism_errors::{DataAvailabilityError, GeneralError};
use std::{self, sync::Arc};
use tokio::sync::{Mutex, RwLock};

#[cfg(target_arch = "wasm32")]
use {
    lumina_node::{blockstore::IndexedDbBlockstore, store::IndexedDbStore},
    lumina_node_wasm::utils::resolve_dnsaddr_multiaddress,
};

#[cfg(not(feature = "uniffi"))]
use libp2p::Multiaddr;

#[cfg(all(not(target_arch = "wasm32"), not(feature = "uniffi")))]
use {redb::Database, tokio::task::spawn_blocking};

#[cfg(not(target_arch = "wasm32"))]
use lumina_node::{blockstore::RedbBlockstore, store::RedbStore};

#[cfg(target_arch = "wasm32")]
pub async fn resolve_bootnodes(bootnodes: &Vec<Multiaddr>) -> Result<Vec<Multiaddr>> {
    let mut bootnodes = bootnodes.clone();
    // Resolve DNS addresses (for now, will be fixed in the future (will be handled by nodebuilder eventually: https://github.com/eigerco/lumina/issues/515))
    for addr in bootnodes.clone() {
        let resolved_addrs = resolve_dnsaddr_multiaddress(addr).await.unwrap();
        bootnodes.extend(resolved_addrs);
    }

    Ok(bootnodes)
}

#[cfg(target_arch = "wasm32")]
pub type LuminaNode = Node<IndexedDbBlockstore, IndexedDbStore>;

#[cfg(not(target_arch = "wasm32"))]
pub type LuminaNode = Node<
    EitherBlockstore<InMemoryBlockstore, RedbBlockstore>,
    EitherStore<InMemoryStore, RedbStore>,
>;

pub struct LightClientConnection {
    pub node: Arc<RwLock<LuminaNode>>,
    pub event_subscriber: Arc<Mutex<EventSubscriber>>,
    pub snark_namespace: Namespace,
}

impl LightClientConnection {
    #[cfg(all(not(target_arch = "wasm32"), not(feature = "uniffi")))]
    async fn setup_stores() -> Result<(RedbBlockstore, RedbStore)> {
        let db = spawn_blocking(|| Database::create("lumina.redb"))
            .await
            .expect("Failed to join")
            .expect("Failed to open the database");
        let db = Arc::new(db);

        let store = RedbStore::new(db.clone()).await.expect("Failed to create a store");
        let blockstore = RedbBlockstore::new(db);
        Ok((blockstore, store))
    }

    #[cfg(target_arch = "wasm32")]
    async fn setup_stores() -> Result<(IndexedDbBlockstore, IndexedDbStore)> {
        let store = IndexedDbStore::new("prism-store")
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create IndexedDbStore: {}", e))?;

        let blockstore = IndexedDbBlockstore::new("prism-blockstore")
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create IndexedDbBlockstore: {}", e))?;

        Ok((blockstore, store))
    }

    pub async fn new(config: &NetworkConfig, node_config: Option<NodeConfig>) -> Result<Self> {
        #[cfg(all(not(target_arch = "wasm32"), not(feature = "uniffi")))]
        let bootnodes = config.celestia_network.canonical_bootnodes().collect::<Vec<Multiaddr>>();
        #[cfg(target_arch = "wasm32")]
        let bootnodes = resolve_bootnodes(&bootnodes).await?;

        #[cfg(target_arch = "wasm32")]
        let (blockstore, store) = Self::setup_stores().await.unwrap();
        #[cfg(all(not(target_arch = "wasm32"), not(feature = "uniffi")))]
        let (blockstore, store) = Self::setup_stores().await?;

        let celestia_config = config
            .celestia_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Celestia config is required but not provided"))?;

        #[cfg(feature = "uniffi")]
        let node_builder = node_config
            .ok_or_else(|| anyhow::anyhow!("Node config is required for uniffi but not provided"))?
            .into_node_builder()
            .await?;
        #[cfg(feature = "uniffi")]
        let (node, event_subscriber) = node_builder.start_subscribed().await?;

        #[cfg(not(feature = "uniffi"))]
        let (node, event_subscriber) = NodeBuilder::new()
            .network(config.celestia_network.clone())
            .store(store)
            .blockstore(blockstore)
            .bootnodes(bootnodes)
            .pruning_delay(celestia_config.pruning_delay)
            .sampling_window(celestia_config.sampling_window)
            .start_subscribed()
            .await?;

        let snark_namespace = create_namespace(&celestia_config.snark_namespace_id)?;

        Ok(LightClientConnection {
            node: Arc::new(RwLock::new(node)),
            event_subscriber: Arc::new(Mutex::new(event_subscriber)),
            snark_namespace,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl LightDataAvailabilityLayer for LightClientConnection {
    // since the lumina node is already started in the constructor, we don't need to start it again. We need the event_subscriber to start forwarding events.
    fn event_subscriber(&self) -> Option<Arc<Mutex<EventSubscriber>>> {
        Some(self.event_subscriber.clone())
    }

    async fn get_finalized_epoch(&self, height: u64) -> Result<Option<FinalizedEpoch>> {
        trace!("searching for epoch on da layer at height {}", height);
        let node = self.node.read().await;
        let header = node.get_header_by_height(height).await?;

        match node.request_all_blobs(&header, self.snark_namespace, None).await {
            Ok(blobs) => {
                if blobs.is_empty() {
                    return Ok(None);
                }
                let blob = blobs.into_iter().next().unwrap();
                let epoch = FinalizedEpoch::try_from(&blob).map_err(|_| {
                    anyhow!(GeneralError::ParsingError(format!(
                        "marshalling blob from height {} to epoch json: {:?}",
                        height, &blob
                    )))
                })?;
                Ok(Some(epoch))
            }
            Err(e) => Err(anyhow!(DataAvailabilityError::DataRetrievalError(
                height,
                format!("getting epoch from da layer: {}", e)
            ))),
        }
    }
}
