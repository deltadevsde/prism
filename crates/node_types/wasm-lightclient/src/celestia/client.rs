use crate::{celestia::config::WasmNodeConfigExt, commands::WorkerResponse};
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
use web_sys::{console, MessagePort};

use super::{CelestiaConfig, FinalizedEpoch};

#[derive(Clone)]
pub struct WasmCelestiaClient {
    pub config: CelestiaConfig,
    pub node: Arc<Node<IndexedDbBlockstore, IndexedDbStore>>,
    pub current_height: Arc<AtomicU64>,
    pub port: MessagePort,
}

impl WasmCelestiaClient {
    pub async fn new(port: MessagePort, config: CelestiaConfig) -> Result<Arc<Self>, JsError> {
        let current_height = Arc::new(AtomicU64::new(config.start_height));

        let mut wasm_node_config = WasmNodeConfig::default(Network::Private);
        let node_config = wasm_node_config.initialize_node_config().await?;

        let (node, mut event_subscriber) = Node::new_subscribed(node_config).await?;
        let node = Arc::new(node);

        let client = Arc::new(Self {
            config,
            node,
            current_height,
            port,
        });

        let client_clone = client.clone();
        spawn_local(async move { client_clone.handle_events(event_subscriber).await });

        Ok(client)
    }

    async fn handle_events(&self, mut event_subscriber: EventSubscriber) {
        while let Ok(event_info) = event_subscriber.recv().await {
            self.process_event(event_info.event).await;
        }
    }

    async fn process_event(&self, event: NodeEvent) -> Result<(), JsError> {
        match event {
            NodeEvent::ShareSamplingResult {
                height, accepted, ..
            } => {
                let message = to_value(&WorkerResponse::SamplingResult { height, accepted })
                    .map_err(|e| {
                        JsError::new(&format!("Failed to serialize sampling result: {:?}", e))
                    })?;
                self.port.post_message(&message);
            }
            NodeEvent::AddedHeaderFromHeaderSub { height } => {
                let epoch_verified = self.verify_epoch(height).await?;
                let message = to_value(&WorkerResponse::EpochVerified(epoch_verified))?;
                self.port.post_message(&message);
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn verify_epoch(&self, height: u64) -> Result<bool, JsError> {
        let namespace = hex::decode(&self.config.snark_namespace_id)
            .map_err(|e| JsError::new(&format!("Invalid namespace: {}", e)))?;
        let header = self.node.get_header_by_height(height).await?;

        match self
            .node
            .request_all_blobs(
                &header,
                Namespace::new_v0(&namespace).unwrap(),
                Some(Duration::from_secs(5)),
            )
            .await
        {
            Ok(blob) => {
                if blob.is_empty() {
                    // no blobs found
                    return Ok(true);
                }
                console::log_2(&"🔍 Verifying epoch at height:".into(), &height.into());
                for b in blob {
                    let epoch = FinalizedEpoch::try_from(&b).map_err(|_| {
                        JsError::new(&format!("Failed to decode blob into FinalizedEpoch"))
                    })?;

                    // mock prover posts an empty proof [0, 0, 0, 0], FinalizedEpoch needs vk_hash
                    /* let mut public_inputs = Vec::with_capacity(64);
                    public_inputs.extend_from_slice(&epoch.prev_commitment);
                    public_inputs.extend_from_slice(&epoch.current_commitment); */

                    // for testing purposes, we use hardcoded public inputs
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
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Err(e) => Err(JsError::new(&format!("❌ Failed to fetch blob: {}", e))),
        }
    }

    pub async fn get_current_height(&self) -> u64 {
        self.current_height.load(Ordering::Relaxed)
    }
}
