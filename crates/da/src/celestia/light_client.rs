use super::utils::{create_namespace, NetworkConfig};
use crate::{FinalizedEpoch, LightDataAvailabilityLayer};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use celestia_types::nmt::Namespace;
use libp2p::Multiaddr;
use log::{error, trace};
use lumina_node::{
    events::{EventSubscriber, NodeEvent},
    Node, NodeBuilder,
};
use prism_errors::{DataAvailabilityError, GeneralError};
use std::{
    self,
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::{broadcast, Mutex, RwLock};

#[cfg(target_arch = "wasm32")]
use {
    lumina_node::{blockstore::IndexedDbBlockstore, store::IndexedDbStore},
    lumina_node_wasm::utils::resolve_dnsaddr_multiaddress,
};

#[cfg(not(target_arch = "wasm32"))]
use {
    lumina_node::{blockstore::RedbBlockstore, store::RedbStore},
    redb::Database,
    tokio::task::spawn_blocking,
};

fn spawn_task<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    #[cfg(target_arch = "wasm32")]
    {
        wasm_bindgen_futures::spawn_local(future);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::spawn(future);
    }
}

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
pub type LuminaNode = Node<RedbBlockstore, RedbStore>;

pub struct LightClientConnection {
    pub node: Arc<RwLock<LuminaNode>>,
    pub event_subscriber: Arc<Mutex<EventSubscriber>>,
    pub snark_namespace: Namespace,
    height_update_tx: broadcast::Sender<u64>,
    sync_target: Arc<AtomicU64>,
}

impl LightClientConnection {
    #[cfg(not(target_arch = "wasm32"))]
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

    // Todo: NodeBuilder Coniguration
    pub async fn new(config: &NetworkConfig) -> Result<Self> {
        let bootnodes = config.celestia_network.canonical_bootnodes().collect::<Vec<Multiaddr>>();
        #[cfg(target_arch = "wasm32")]
        let bootnodes = resolve_bootnodes(&bootnodes).await?;

        #[cfg(target_arch = "wasm32")]
        let (blockstore, store) = Self::setup_stores().await.unwrap();
        #[cfg(not(target_arch = "wasm32"))]
        let (blockstore, store) = Self::setup_stores().await?;

        let celestia_config = config
            .celestia_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Celestia config is required but not provided"))?;

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
        let (height_update_tx, _) = broadcast::channel(100);

        Ok(LightClientConnection {
            node: Arc::new(RwLock::new(node)),
            event_subscriber: Arc::new(Mutex::new(event_subscriber)),
            snark_namespace,
            height_update_tx,
            sync_target: Arc::new(AtomicU64::new(celestia_config.start_height)),
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl LightDataAvailabilityLayer for LightClientConnection {
    async fn start(&self) -> Result<()> {
        let sync_target = self.sync_target.clone();
        let height_update_tx = self.height_update_tx.clone();
        let event_subscriber = self.event_subscriber.clone();

        spawn_task(handle_events(
            sync_target,
            height_update_tx,
            event_subscriber,
        ));

        Ok(())
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

    fn subscribe_to_heights(&self) -> broadcast::Receiver<u64> {
        self.height_update_tx.subscribe()
    }
}

async fn handle_events(
    sync_target: Arc<AtomicU64>,
    height_update_tx: broadcast::Sender<u64>,
    event_subscriber: Arc<Mutex<EventSubscriber>>,
) {
    loop {
        let mut event_subscriber = event_subscriber.lock().await;

        match event_subscriber.recv().await {
            Ok(event_info) => match event_info.event {
                NodeEvent::AddedHeaderFromHeaderSub { height } => {
                    sync_target.store(height, Ordering::Relaxed);
                    let _ = height_update_tx.send(height);
                    trace!("updated sync target for height {}", height);
                }
                _ => {
                    #[cfg(not(target_arch = "wasm32"))]
                    trace!("event: {:?}", event_info.event);
                }
            },
            Err(e) => {
                error!("Error receiving event: {:?}", e);
                break;
            }
        }
    }
}
