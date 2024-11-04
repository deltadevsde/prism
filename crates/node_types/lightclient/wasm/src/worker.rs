use anyhow::Context;
use celestia_types::{nmt::Namespace, Blob};
use libp2p::identity::Keypair;
use lumina_node::{
    blockstore::IndexedDbBlockstore, events::NodeEvent, network::network_id, store::IndexedDbStore,
    Node, NodeConfig,
};
use lumina_node_wasm::{
    client::WasmNodeConfig,
    utils::{resolve_dnsaddr_multiaddress, Network},
};
use serde_wasm_bindgen::to_value;
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use web_sys::{console, MessagePort};

use crate::{
    commands::{LightClientCommand, WorkerResponse},
    worker_communication::WorkerServer,
};

use serde::{Deserialize, Serialize};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::broadcast;
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FinalizedEpoch {
    pub height: u64,
    pub prev_commitment: [u8; 32],
    pub current_commitment: [u8; 32],
    pub proof: Vec<u8>,
    pub signature: Option<String>,
}

impl TryFrom<&Blob> for FinalizedEpoch {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        bincode::deserialize(&value.data).context(format!(
            "Failed to decode blob into FinalizedEpoch: {value:?}"
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelestiaConfig {
    pub node_url: String,
    pub start_height: u64,
    pub snark_namespace_id: String,
    pub operation_namespace_id: Option<String>,
}

impl Default for CelestiaConfig {
    fn default() -> Self {
        Self {
            node_url: "ws://localhost:26658".to_string(), // Must be WebSocket
            start_height: 0,
            snark_namespace_id: "00000000000000de1008".to_string(),
            operation_namespace_id: Some("00000000000000de1009".to_string()),
        }
    }
}

#[derive(Clone)]
pub struct WasmCelestiaClient {
    config: CelestiaConfig,
    node: Arc<Node<IndexedDbBlockstore, IndexedDbStore>>,
    current_height: Arc<AtomicU64>,
    height_update_tx: broadcast::Sender<u64>,
}

impl WasmCelestiaClient {
    pub async fn new(config: CelestiaConfig) -> Result<Self, JsError> {
        let (height_update_tx, _) = broadcast::channel(100);
        let current_height = Arc::new(AtomicU64::new(config.start_height));
        let wasm_node_config = WasmNodeConfig::default(Network::Arabica);

        let network_id = network_id(wasm_node_config.network.into());
        let store = IndexedDbStore::new(network_id)
            .await
            .map_err(|e| JsError::new(&format!("Failed to open the store: {}", e)))?;

        let blockstore = IndexedDbBlockstore::new(&format!("{network_id}-blockstore"))
            .await
            .map_err(|e| JsError::new(&format!("Failed to open the blockstore: {}", e)))?;

        let p2p_local_keypair = Keypair::generate_ed25519();

        let mut p2p_bootnodes = Vec::with_capacity(wasm_node_config.bootnodes.len());
        for addr in wasm_node_config.bootnodes {
            console::log_1(&format!("🚀 Adding bootnode: {}", addr).into());
            let addr = addr
                .parse()
                .map_err(|e| JsError::new(&format!("Invalid multiaddr '{}': {}", addr, e)))?;
            let resolved_addrs = resolve_dnsaddr_multiaddress(addr)
                .await
                .map_err(|e| JsError::new(&format!("Invalid multiaddr '{}'", e)))?;
            p2p_bootnodes.extend(resolved_addrs.into_iter());
        }

        let syncing_window = wasm_node_config
            .custom_syncing_window_secs
            .map(|d| Duration::from_secs(d.into()));

        let node_config = NodeConfig {
            network_id: network_id.to_string(),
            p2p_bootnodes,
            p2p_local_keypair,
            p2p_listen_on: vec![],
            sync_batch_size: 128,
            custom_syncing_window: syncing_window,
            blockstore,
            store,
        };

        let (node, mut event_subscriber) = Node::new_subscribed(node_config).await?;

        let client = Self {
            config: config.clone(),
            node: Arc::new(node),
            current_height: current_height.clone(),
            height_update_tx: height_update_tx.clone(),
        };

        let config_for_verifier = config.clone();
        let client_for_verifier = client.clone();

        wasm_bindgen_futures::spawn_local(async move {
            while let Ok(event) = event_subscriber.recv().await {
                if let NodeEvent::AddedHeaderFromHeaderSub { height } = event.event {
                    console::log_2(&"📦 New block height:".into(), &height.to_string().into());

                    current_height.store(height, Ordering::Relaxed);
                    if let Err(e) = height_update_tx.send(height) {
                        console::log_2(
                            &"❌ Failed to send height update:".into(),
                            &e.to_string().into(),
                        );
                    }
                    console::log_2(&"📦 New block height:".into(), &height.to_string().into());

                    // Verify epoch using cloned client and config, because i can't pass self
                    match client_for_verifier.verify_epoch(height).await {
                        Ok(true) => {
                            console::log_2(&"✅ Epoch verified at height:".into(), &height.into())
                        }
                        Ok(false) => {
                            console::log_2(&"⚠️ No epoch found at height:".into(), &height.into())
                        }
                        Err(e) => console::log_2(&"❌ Error verifying epoch...".into(), &e.into()),
                    }
                }
            }
        });

        Ok(client)
    }

    pub async fn get_current_height(&self) -> u64 {
        self.current_height.load(Ordering::Relaxed)
    }

    pub async fn verify_epoch(&self, height: u64) -> Result<bool, JsError> {
        let namespace = hex::decode(&self.config.snark_namespace_id)
            .map_err(|e| JsError::new(&format!("Invalid namespace: {}", e)))?;
        let header = self.node.get_header_by_height(height).await?;

        match self
            .node
            .request_all_blobs(&header, Namespace::new_v0(&namespace).unwrap(), None)
            .await
        {
            Ok(blob) => {
                if blob.is_empty() {
                    console::log_2(&"🔍 No blobs found at height:".into(), &height.into());
                    return Ok(false);
                }
                console::log_2(&"🔍 Verifying epoch at height:".into(), &height.into());
                console::log_2(&"🔍 Epoch data:".into(), &to_value(&blob).unwrap());
                for b in blob {
                    let epoch = FinalizedEpoch::try_from(&b).map_err(|_| {
                        JsError::new(&format!("Failed to decode blob into FinalizedEpoch"))
                    })?;
                    let public_inputs = Vec::with_capacity(64);
                    public_inputs.extend_from_slice(&epoch.prev_commitment);
                    public_inputs.extend_from_slice(&epoch.current_commitment);
                    Groth16Verifier::verify(&epoch.proof, &public_inputs, lms, *GROTH16_VK_BYTES)
                        .is_ok();
                    console::log_2(&"🔍 Epoch:".into(), &to_value(&epoch).unwrap());
                }
                Ok(true)
            }
            Err(e) => Err(JsError::new(&format!("Failed to fetch blob: {}", e))),
        }
    }

    pub fn subscribe_to_heights(&self) -> broadcast::Receiver<u64> {
        self.height_update_tx.subscribe()
    }
}

#[wasm_bindgen]
pub struct LightClientWorker {
    server: WorkerServer,
    celestia: WasmCelestiaClient,
}

#[wasm_bindgen]
impl LightClientWorker {
    #[wasm_bindgen(constructor)]
    pub async fn new(port: MessagePort) -> Result<LightClientWorker, JsError> {
        console::log_1(&"• Initializing LightClientWorker  ✔".into());
        let mut server = WorkerServer::new();
        server.initialize(port)?;

        let celestia = WasmCelestiaClient::new(CelestiaConfig::default()).await?;

        console::log_1(&"• Server registered  ✔".into());

        Ok(Self { server, celestia })
    }

    pub async fn run(&mut self) -> Result<(), JsError> {
        console::log_1(&"• Starting LightClientWorker ✔".into());
        while let Ok(command) = self.server.recv().await {
            let response = match command {
                LightClientCommand::InternalPing => WorkerResponse::InternalPong,
                LightClientCommand::VerifyEpoch { height } => {
                    console::log_2(&"• Verifying epoch....".into(), &height.into());
                    match self.celestia.verify_epoch(height).await {
                        Ok(true) => WorkerResponse::EpochVerified,
                        Ok(false) => WorkerResponse::Error("No epoch data found".to_string()),
                        Err(e) => {
                            WorkerResponse::Error(format!("Failed to verify epoch...{:?}", e,))
                        }
                    }
                }
                LightClientCommand::GetCurrentHeight => {
                    WorkerResponse::CurrentHeight(self.celestia.get_current_height().await)
                }
                LightClientCommand::SetProverKey(_) => WorkerResponse::ProverKeySet, // TODO if needed
            };

            self.server.respond(response);
        }
        Ok(())
    }
}
