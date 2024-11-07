use crate::celestia::config::WasmNodeConfigExt;
use celestia_types::nmt::Namespace;
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
    config: CelestiaConfig,
    node: Arc<Node<IndexedDbBlockstore, IndexedDbStore>>,
    current_height: Arc<AtomicU64>,
}

impl WasmCelestiaClient {
    pub async fn new(config: CelestiaConfig) -> Result<Self, JsError> {
        let bridge_addr = CelestiaConfig::fetch_bridge_webtransport_multiaddr().await;

        console::log_2(
            &"🚀 Bridge address:".into(),
            &bridge_addr.to_string().into(),
        );

        let current_height = Arc::new(AtomicU64::new(config.start_height));

        let mut wasm_node_config = WasmNodeConfig::default(Network::Private);
        wasm_node_config.set_bridge_bootnode(bridge_addr.to_string());
        let node_config = wasm_node_config.initialize_node_config().await?;

        let (node, mut event_subscriber) = Node::new_subscribed(node_config).await?;

        let client = Self {
            config,
            node: Arc::new(node),
            current_height: current_height.clone(),
        };

        let client_for_verifier = client.clone();

        spawn_local(async move {
            console::log_1(&"📦 Subscribing to events...".into());

            loop {
                match event_subscriber.recv().await {
                    Ok(event) => {
                        if let NodeEvent::SamplingStarted {
                            height,
                            square_width,
                            ref shares,
                        } = event.event
                        {
                            console::log_4(
                                &"📦 Sampling started:".into(),
                                &height.into(),
                                &square_width.into(),
                                &shares.len().into(),
                            );
                        };
                        if let NodeEvent::ShareSamplingResult {
                            height,
                            square_width,
                            row,
                            column,
                            accepted,
                        } = event.event.clone()
                        {
                            console::log_3(
                                &"📦 Share sampling result:".into(),
                                &height.into(),
                                &accepted.into(),
                            );
                        }
                        if let NodeEvent::SamplingFinished {
                            height,
                            accepted,
                            took,
                        } = event.event
                        {
                            console::log_2(&"📦 Sampling finished:".into(), &height.into());
                        }
                        if let NodeEvent::AddedHeaderFromHeaderSub { height } = event.event {
                            console::log_2(
                                &"📦 New block height:".into(),
                                &height.to_string().into(),
                            );
                            current_height.store(height, Ordering::Relaxed);

                            // Verify epoch using cloned client and config, because i can't pass self
                            match client_for_verifier.verify_epoch(height).await {
                                Ok(true) => console::log_2(
                                    &"✅ Epoch verified at height:".into(),
                                    &height.into(),
                                ),
                                Ok(false) => console::log_2(
                                    &"⚠️ No epoch found at height:".into(),
                                    &height.into(),
                                ),
                                Err(e) => {
                                    console::error_1(
                                        &format!("❌ Error verifying epoch: {:?}", e).into(),
                                    );
                                    // Don't break the loop on epoch verification error
                                }
                            }
                        }
                    }
                    Err(e) => {
                        console::error_1(&format!("❌ Error receiving event: {:?}", e).into());
                        // Maybe the channel was closed? Let's try to continue anyway
                        tokio::time::sleep(Duration::from_secs(1)).await;
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
        console::log_2(&"🔍 Namespace:".into(), &to_value(&namespace).unwrap());
        let header = self.node.get_header_by_height(height).await?;
        console::log_2(
            &"Header fetched".into(),
            &to_value(&header.clone()).unwrap(),
        );

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
                    console::log_2(&"🔍 No blobs found at height:".into(), &height.into());
                    return Ok(false);
                }
                console::log_2(&"🔍 Verifying epoch at height:".into(), &height.into());
                console::log_2(&"🔍 Epoch data:".into(), &to_value(&blob).unwrap());
                for b in blob {
                    let epoch = FinalizedEpoch::try_from(&b).map_err(|_| {
                        JsError::new(&format!("Failed to decode blob into FinalizedEpoch"))
                    })?;

                    let vk_hash_bytes = &epoch.proof[..4];
                    let encoded_proof = &epoch.proof[4..];
                    let vk_hash = hex::encode(vk_hash_bytes);

                    let mut public_inputs = Vec::with_capacity(64);
                    public_inputs.extend_from_slice(&epoch.prev_commitment);
                    public_inputs.extend_from_slice(&epoch.current_commitment);

                    if !Groth16Verifier::verify(
                        encoded_proof,
                        &public_inputs,
                        &vk_hash,
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
}
