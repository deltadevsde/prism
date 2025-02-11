use crate::{
    config::{CelestiaConfig, NetworkConfig},
    FinalizedEpoch, LightClientDataAvailabilityLayer,
};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use celestia_types::{nmt::Namespace, Blob};
use log::{error, trace};
use lumina_node::{
    events::{EventSubscriber, NodeEvent},
    network::Network as CelestiaNetwork,
    Node, NodeBuilder,
};
use prism_errors::{DataAvailabilityError, GeneralError};
use prism_keys::VerifyingKey;
use prism_serde::{self, base64::FromBase64, binary::FromBinary, hex::FromHex};
use serde::{Deserialize, Serialize};
use std::{
    self,
    future::Future,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::sync::{broadcast, Mutex, RwLock};

#[cfg(target_arch = "wasm32")]
use {
    libp2p::Multiaddr,
    lumina_node::{blockstore::IndexedDbBlockstore, store::IndexedDbStore},
    lumina_node_wasm::utils::resolve_dnsaddr_multiaddress,
    wasm_bindgen::JsError,
    wasm_bindgen_futures::spawn_local,
    web_sys::console,
};

#[cfg(not(target_arch = "wasm32"))]
use {
    crate::FullNodeDataAvailabilityLayer,
    celestia_rpc::{BlobClient, Client, HeaderClient, TxConfig},
    celestia_types::AppVersion,
    log::{debug, warn},
    lumina_node::{blockstore::RedbBlockstore, store::RedbStore},
    prism_common::transaction::Transaction,
    prism_serde::binary::ToBinary,
    redb::Database,
    tokio::{task::spawn, task::spawn_blocking},
};

fn create_namespace(namespace_hex: &str) -> Result<Namespace> {
    let decoded_hex = Vec::<u8>::from_hex(namespace_hex).context(format!(
        "Failed to decode namespace hex '{}'",
        namespace_hex
    ))?;

    Namespace::new_v0(&decoded_hex).context(format!(
        "Failed to create namespace from '{}'",
        namespace_hex
    ))
}

impl TryFrom<&Blob> for FinalizedEpoch {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        FinalizedEpoch::decode_from_bytes(&value.data).map_err(|_| {
            anyhow!(format!(
                "Failed to decode blob into FinalizedEpoch: {value:?}"
            ))
        })
    }
}

#[cfg(target_arch = "wasm32")]
pub type LuminaNode = Node<IndexedDbBlockstore, IndexedDbStore>;

#[cfg(not(target_arch = "wasm32"))]
pub type LuminaNode = Node<RedbBlockstore, RedbStore>;

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

    #[cfg(target_arch = "wasm32")]
    async fn get_bootnodes(network: &CelestiaNetwork) -> Result<Vec<Multiaddr>> {
        let mut bootnodes: Vec<Multiaddr> = [
            "/dnsaddr/da-bridge-1-mocha-4.celestia-mocha.com/p2p/12D3KooWCBAbQbJSpCpCGKzqz3rAN4ixYbc63K68zJg9aisuAajg",
            "/dnsaddr/da-bridge-2-mocha-4.celestia-mocha.com/p2p/12D3KooWK6wJkScGQniymdWtBwBuU36n6BRXp9rCDDUD6P5gJr3G",
            "/dnsaddr/da-full-1-mocha-4.celestia-mocha.com/p2p/12D3KooWCUHPLqQXZzpTx1x3TAsdn3vYmTNDhzg66yG8hqoxGGN8",
            "/dnsaddr/da-full-2-mocha-4.celestia-mocha.com/p2p/12D3KooWR6SHsXPkkvhCRn6vp1RqSefgaT1X1nMNvrVjU2o3GoYy",
            "/dnsaddr/mocha-boot.pops.one/p2p/12D3KooWDzNyDSvTBdKQAmnsUdAyQCQWwM3ReXTmPaaf6LzfNwRs",
            "/dnsaddr/celestia-mocha.qubelabs.io/p2p/12D3KooWQVmHy7JpfxpKZfLjvn12GjvMgKrWdsHkFbV2kKqQFBCG",
        ].into_iter().map(str::parse).collect::<Result<_, _>>()?;

        // Resolve DNS addresses (for now, will be fixed in the future (will be handled by nodebuilder eventually: https://github.com/eigerco/lumina/issues/515))
        for addr in bootnodes.clone() {
            let resolved_addrs = resolve_dnsaddr_multiaddress(addr).await.unwrap();
            bootnodes.extend(resolved_addrs);
        }

        Ok(bootnodes)
    }

    // Todo: NodeBuilder Coniguration
    // Todo: handle bootnodes correctly
    pub async fn new(config: &NetworkConfig) -> Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        let bootnodes = Vec::new();

        #[cfg(target_arch = "wasm32")]
        let bootnodes = Self::get_bootnodes(&config.celestia_network).await?;

        #[cfg(target_arch = "wasm32")]
        {
            // only for logging
            let bootnode_strings: Vec<String> =
                bootnodes.iter().map(|addr| addr.to_string()).collect();
            console::log_2(
                &"bootnodes: ".into(),
                &serde_wasm_bindgen::to_value(&bootnode_strings).unwrap().into(),
            );
        }

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
            .start_subscribed()
            .await?;

        let snark_namespace = create_namespace(&celestia_config.snark_namespace_id)?;
        let (height_update_tx, _) = broadcast::channel(100);

        Ok(LightClientConnection {
            node: Arc::new(RwLock::new(node)),
            event_subscriber: Arc::new(Mutex::new(event_subscriber)),
            snark_namespace,
            height_update_tx,
            sync_target: Arc::new(AtomicU64::new(4500000)),
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl LightClientDataAvailabilityLayer for LightClientConnection {
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

#[cfg(not(target_arch = "wasm32"))]
pub struct CelestiaConnection {
    pub client: celestia_rpc::Client,
    pub snark_namespace: Namespace,
    pub operation_namespace: Namespace,

    height_update_tx: broadcast::Sender<u64>,
    sync_target: Arc<AtomicU64>,
}

#[cfg(not(target_arch = "wasm32"))]
impl CelestiaConnection {
    pub async fn new(config: &CelestiaConfig, auth_token: Option<&str>) -> Result<Self> {
        let client = Client::new(&config.connection_string, auth_token)
            .await
            .context("Failed to initialize websocket connection")
            .map_err(|e| DataAvailabilityError::NetworkError(e.to_string()))?;

        let snark_namespace = create_namespace(&config.snark_namespace_id).context(format!(
            "Failed to create snark namespace from: '{}'",
            &config.snark_namespace_id
        ))?;

        let operation_namespace =
            create_namespace(&config.operation_namespace_id).context(format!(
                "Failed to create operation namespace from: '{}'",
                &config.operation_namespace_id
            ))?;

        let (height_update_tx, _) = broadcast::channel(100);

        Ok(CelestiaConnection {
            client,
            snark_namespace,
            operation_namespace,
            height_update_tx,
            sync_target: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl FullNodeDataAvailabilityLayer for CelestiaConnection {
    async fn get_latest_height(&self) -> Result<u64> {
        Ok(self.sync_target.load(Ordering::Relaxed))
    }

    async fn initialize_sync_target(&self) -> Result<u64> {
        let height = HeaderClient::header_network_head(&self.client)
            .await
            .context("Failed to get network head from DA layer")
            .map(|extended_header| extended_header.header.height.value())?;

        self.sync_target.store(height, Ordering::Relaxed);
        Ok(height)
    }

    async fn get_finalized_epoch(&self, height: u64) -> Result<Option<FinalizedEpoch>> {
        trace!("searching for epoch on da layer at height {}", height);

        match BlobClient::blob_get_all(&self.client, height, &[self.snark_namespace]).await {
            Ok(maybe_blobs) => match maybe_blobs {
                Some(blobs) => blobs
                    .into_iter()
                    .next()
                    .map(|blob| {
                        FinalizedEpoch::try_from(&blob).map_err(|_| {
                            anyhow!(GeneralError::ParsingError(format!(
                                "marshalling blob from height {} to epoch json: {:?}",
                                height, &blob
                            )))
                        })
                    })
                    .transpose(),
                None => Ok(None),
            },
            Err(err) => {
                if err.to_string().contains("blob: not found") {
                    Ok(None)
                } else {
                    Err(anyhow!(DataAvailabilityError::DataRetrievalError(
                        height,
                        format!("getting epoch from da layer: {}", err)
                    )))
                }
            }
        }
    }

    async fn submit_finalized_epoch(&self, epoch: FinalizedEpoch) -> Result<u64> {
        debug!("posting {}th epoch to da layer", epoch.height);

        let data = epoch.encode_to_bytes().map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::ParsingError(format!(
                "serializing epoch {}: {}",
                epoch.height, e
            )))
        })?;

        let blob = Blob::new(self.snark_namespace, data, AppVersion::V3).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::BlobCreationError(e.to_string()))
        })?;

        self.client
            .blob_submit(&[blob], TxConfig::default())
            .await
            .map_err(|e| anyhow!(DataAvailabilityError::SubmissionError(e.to_string())))
    }

    async fn get_transactions(&self, height: u64) -> Result<Vec<Transaction>> {
        trace!(
            "searching for transactions on da layer at height {}",
            height
        );
        let maybe_blobs =
            BlobClient::blob_get_all(&self.client, height, &[self.operation_namespace])
                .await
                .map_err(|e| {
                    anyhow!(DataAvailabilityError::DataRetrievalError(
                        height,
                        format!("getting transactions from da layer: {}", e)
                    ))
                })?;

        let blobs = match maybe_blobs {
            Some(blobs) => blobs,
            None => return Ok(vec![]),
        };

        let transactions = blobs
            .iter()
            .filter_map(|blob| match Transaction::try_from(blob) {
                Ok(transaction) => Some(transaction),
                Err(e) => {
                    warn!(
                        "Failed to parse blob from height {} to transaction: {:?}",
                        height, e
                    );
                    None
                }
            })
            .collect();

        Ok(transactions)
    }

    async fn submit_transactions(&self, transactions: Vec<Transaction>) -> Result<u64> {
        debug!("posting {} transactions to DA layer", transactions.len());
        let blobs: Result<Vec<Blob>, _> = transactions
            .iter()
            .map(|transaction| {
                let data = transaction
                    .encode_to_bytes()
                    .context(format!("Failed to serialize transaction {:?}", transaction))
                    .map_err(|e| {
                        DataAvailabilityError::GeneralError(GeneralError::ParsingError(
                            e.to_string(),
                        ))
                    })?;

                Blob::new(self.operation_namespace, data, AppVersion::V3)
                    .context(format!(
                        "Failed to create blob for transaction {:?}",
                        transaction
                    ))
                    .map_err(|e| {
                        DataAvailabilityError::GeneralError(GeneralError::BlobCreationError(
                            e.to_string(),
                        ))
                    })
            })
            .collect();

        let blobs = blobs?;

        for (i, blob) in blobs.iter().enumerate() {
            trace!("blob {}: {:?}", i, blob);
        }

        self.client
            .blob_submit(&blobs, TxConfig::default())
            .await
            .map_err(|e| anyhow!(DataAvailabilityError::SubmissionError(e.to_string())))
    }

    fn subscribe_to_heights(&self) -> broadcast::Receiver<u64> {
        self.height_update_tx.subscribe()
    }

    async fn start(&self) -> Result<()> {
        let mut header_sub = HeaderClient::header_subscribe(&self.client)
            .await
            .context("Failed to subscribe to headers from DA layer")?;

        let sync_target = self.sync_target.clone();
        let height_update_tx = self.height_update_tx.clone();

        spawn(async move {
            while let Some(extended_header_result) = header_sub.next().await {
                match extended_header_result {
                    Ok(extended_header) => {
                        let height = extended_header.header.height.value();
                        sync_target.store(height, Ordering::Relaxed);
                        // todo: correct error handling
                        let _ = height_update_tx.send(height);
                        trace!("updated sync target for height {}", height);
                    }
                    Err(e) => {
                        error!("Error retrieving header from DA layer: {}", e);
                    }
                }
            }
        });
        Ok(())
    }
}
