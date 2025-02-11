/* use crate::commands::WorkerResponse;
use celestia_types::nmt::Namespace;
use libp2p::Multiaddr;
use lumina_node::{
    blockstore::IndexedDbBlockstore,
    events::{EventSubscriber, NodeEvent},
    network::Network,
    store::IndexedDbStore,
    Node, NodeBuilder,
};
use lumina_node_wasm::utils::resolve_dnsaddr_multiaddress;

use prism_lightclient::LightClient;
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

use super::FinalizedEpoch;

#[derive(Clone)]
pub struct WasmCelestiaClient {
    pub light_client: Arc<LightClient>,
    pub port: MessagePort,
}

impl WasmCelestiaClient {
    pub async fn new(port: MessagePort) -> Result<Arc<Self>, JsError> {
        let (node, event_subscriber) = Self::setup_node().await?;
        console::log_1(&"🚀 Node started".into());

        let node = Arc::new(node);
        let client = Arc::new(Self {
            node,
            current_height: Arc::new(AtomicU64::new(4279075)),
            port,
        });

        let client_clone = client.clone();
        spawn_local(async move { client_clone.handle_events(event_subscriber).await });

        Ok(client)
    }

    async fn setup_node(
    ) -> Result<(Node<IndexedDbBlockstore, IndexedDbStore>, EventSubscriber), JsError> {
        let network = Network::Mocha; // config handling
        let network_id = network.id();

        // Get canonical bootnodes
        let mut bootnodes = network.canonical_bootnodes().collect::<Vec<Multiaddr>>();

        // Resolve DNS addresses (for now, will be fixed in the future (will be handled by nodebuilder eventually: https://github.com/eigerco/lumina/issues/515))
        for addr in bootnodes.clone() {
            let resolved_addrs = resolve_dnsaddr_multiaddress(addr)
                .await
                .map_err(|e| JsError::new(&format!("Failed to resolve DNS: {}", e)))?;
            bootnodes.extend(resolved_addrs);
        }

        // Setup storage
        let store = IndexedDbStore::new(network_id)
            .await
            .map_err(|e| JsError::new(&format!("Failed to open store: {}", e)))?;
        let blockstore = IndexedDbBlockstore::new(&format!("{network_id}-blockstore"))
            .await
            .map_err(|e| JsError::new(&format!("Failed to open blockstore: {}", e)))?;

        // Configure and start node
        NodeBuilder::new()
            .store(store)
            .blockstore(blockstore)
            .bootnodes(bootnodes)
            .network(network)
            .sync_batch_size(128)
            .sampling_window(Duration::from_secs(60 * 60 * 24 * 30))
            .start_subscribed()
            .await
            .map_err(|e| JsError::new(&format!("Failed to start node: {}", e)))
    }

    async fn handle_events(&self, mut event_subscriber: EventSubscriber) {
        while let Ok(event_info) = event_subscriber.recv().await {
            if let Err(e) = self.process_event(event_info.event).await {
                console::error_1(&format!("Failed to process event: {:?}", e).into());
            }
        }
    }

    async fn process_event(&self, event: NodeEvent) -> Result<(), JsError> {
        match event {
            NodeEvent::ShareSamplingResult {
                height, accepted, ..
            } => {
                let message = to_value(&WorkerResponse::SamplingResult { height, accepted })?;
                self.port.post_message(&message);
            }
            NodeEvent::AddedHeaderFromHeaderSub { height } => {
                console::log_2(
                    &"Added header from header sub at height:".into(),
                    &height.into(),
                );
                let current_position = self.current_height.load(Ordering::Relaxed);

                for i in current_position..height {
                    let epoch_verified = self.verify_epoch(i).await?;
                    let message = to_value(&WorkerResponse::EpochVerified {
                        verified: epoch_verified,
                        height: i,
                    })?;
                    self.port.post_message(&message);
                }

                self.current_height.store(height, Ordering::Relaxed);
                let message = to_value(&WorkerResponse::CurrentHeight(height))?;
                self.port.post_message(&message);
            }
            _ => {
                console::log_1(&format!("Received event: {:?}", event).into());
            }
        }
        Ok(())
    }

    pub async fn verify_epoch(&self, height: u64) -> Result<bool, JsError> {
        let namespace =
            hex::decode("000000000000000000000000000000000000707269736d5350457330".to_string())
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
                    return Ok(true);
                }
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
 */
