use crate::celestia::config::WasmNodeConfigExt;
use celestia_types::nmt::Namespace;
use lumina_node::{
    blockstore::IndexedDbBlockstore,
    events::{EventSubscriber, NodeEvent},
    store::IndexedDbStore,
    Node,
};
use lumina_node_wasm::{client::WasmNodeConfig, utils::Network};
use serde_wasm_bindgen::to_value;
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::console;

use super::{CelestiaConfig, FinalizedEpoch};

#[derive(Clone)]
pub struct WasmCelestiaClient {
    pub config: CelestiaConfig,
    pub node: Arc<Node<IndexedDbBlockstore, IndexedDbStore>>,
    pub current_height: Arc<AtomicU64>,
}

impl WasmCelestiaClient {
    pub async fn new(config: CelestiaConfig) -> Result<Self, JsError> {
        let current_height = Arc::new(AtomicU64::new(config.start_height));

        let mut wasm_node_config = WasmNodeConfig::default(Network::Private);
        let node_config = wasm_node_config.initialize_node_config().await?;

        let (node, mut event_subscriber) = Node::new_subscribed(node_config).await?;
        let node = Arc::new(node);

        let client = Self {
            config,
            node: node.clone(),
            current_height: current_height.clone(),
        };

        spawn_local(Self::handle_events(node, event_subscriber, current_height));

        Ok(client)
    }

    async fn handle_events(
        node: Arc<Node<IndexedDbBlockstore, IndexedDbStore>>,
        mut event_subscriber: EventSubscriber,
        current_height: Arc<AtomicU64>,
    ) {
        while let Ok(event_info) = event_subscriber.recv().await {
            Self::process_event(event_info.event, &node, &current_height).await;
        }
    }

    async fn process_event(
        event: NodeEvent,
        node: &Arc<Node<IndexedDbBlockstore, IndexedDbStore>>,
        current_height: &AtomicU64,
    ) {
        match event {
            NodeEvent::ShareSamplingResult {
                height, accepted, ..
            } => {
                console::log_3(
                    &"📦 Share sampling result:".into(),
                    &height.into(),
                    &accepted.into(),
                );
            }
            NodeEvent::AddedHeaderFromHeaderSub { height } => {
                current_height.store(height, Ordering::Relaxed);
                let node = node.clone();
                spawn_local(async move {
                    match Self::verify_epoch(node, height).await {
                        Ok(true) => {
                            console::log_2(&"✅ Epoch verified at height:".into(), &height.into())
                        }
                        Ok(false) => {
                            console::log_2(&"⚠️ No epoch found at height:".into(), &height.into())
                        }
                        Err(e) => {
                            console::error_1(&format!("❌ Error verifying epoch: {:?}", e).into())
                        }
                    }
                });
            }
            _ => {}
        }
    }

    pub async fn verify_epoch(
        node: Arc<Node<IndexedDbBlockstore, IndexedDbStore>>,
        height: u64,
    ) -> Result<bool, JsError> {
        let namespace = hex::decode(&"00000000000000de1008".to_string())
            .map_err(|e| JsError::new(&format!("Invalid namespace: {}", e)))?;
        let header = node.get_header_by_height(height).await?;

        match node
            .request_all_blobs(
                &header,
                Namespace::new_v0(&namespace).unwrap(),
                Some(Duration::from_secs(7)),
            )
            .await
        {
            Ok(blob) => {
                if blob.is_empty() {
                    console::log_2(&"🔍 No blobs found at height:".into(), &height.into());
                    return Ok(false);
                }
                console::log_2(&"🔍 Verifying epoch at height:".into(), &height.into());
                for b in blob {
                    let epoch = FinalizedEpoch::try_from(&b).map_err(|_| {
                        JsError::new(&format!("Failed to decode blob into FinalizedEpoch"))
                    })?;

                    console::log_2(&"🔍 Epoch:".into(), &to_value(&epoch).unwrap());

                    // mock prover posts an empty proof [0, 0, 0, 0], FinalizedEpoch needs vk_hash
                    /* let mut public_inputs = Vec::with_capacity(64);
                    public_inputs.extend_from_slice(&epoch.prev_commitment);
                    public_inputs.extend_from_slice(&epoch.current_commitment); */

                    let hardcoded_public_inputs_string = "e80300004d170000430e0000";
                    let public_inputs = hex::decode(hardcoded_public_inputs_string)
                        .map_err(|e| JsError::new(&format!("Invalid public inputs: {}", e)))?;

                    if !Groth16Verifier::verify(
                        &epoch.proof,
                        &public_inputs,
                        &epoch.vk_hash,
                        *GROTH16_VK_BYTES,
                    )
                    .is_ok()
                    {
                        console::log_2(
                            &"❌ Epoch verification failed at height:".into(),
                            &height.into(),
                        );
                        return Ok(false);
                    }
                    console::log_2(&"🔍 Epoch:".into(), &to_value(&epoch).unwrap());
                }
                Ok(true)
            }
            Err(e) => {
                console::error_1(&format!("❌ Failed to fetch blobs: {}", e).into());
                Err(JsError::new(&format!("Failed to fetch blob: {}", e)))
            }
        }
    }

    pub async fn get_current_height(&self) -> u64 {
        self.current_height.load(Ordering::Relaxed)
    }
}
