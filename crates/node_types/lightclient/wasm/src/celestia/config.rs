// we'll remove these files probably eventually but for a better overview

use celestia_rpc::{Client, P2PClient};
use libp2p::{identity::Keypair, multiaddr::Protocol, Multiaddr};
use lumina_node::{
    blockstore::IndexedDbBlockstore, network::network_id, store::IndexedDbStore, NodeConfig,
};
use lumina_node_wasm::{
    client::WasmNodeConfig,
    utils::{resolve_dnsaddr_multiaddress, Network},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wasm_bindgen::JsError;
use web_sys::console;

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
            node_url: "ws://localhost:26658".to_string(),
            start_height: 3093687,
            snark_namespace_id: "00000000000000de1008".to_string(),
            operation_namespace_id: Some("00000000000000de1009".to_string()),
        }
    }
}

impl CelestiaConfig {
    pub async fn fetch_bridge_webtransport_multiaddr() -> Multiaddr {
        let rpc_client = Client::new("ws://127.0.0.1:26658").await.unwrap();
        let bridge_info = rpc_client.p2p_info().await.unwrap();

        let mut ma = bridge_info
            .addrs
            .into_iter()
            .find(|ma| {
                let not_localhost =
                    !ma.iter().any(|prot| prot == Protocol::Ip4("127.0.0.1".parse().unwrap()));
                let webtransport = ma.protocol_stack().any(|protocol| protocol == "webtransport");
                not_localhost && webtransport
            })
            .expect("Bridge doesn't listen on webtransport");

        if !ma.protocol_stack().any(|protocol| protocol == "p2p") {
            ma.push(Protocol::P2p(bridge_info.id.into()))
        }

        ma
    }
}

pub trait WasmNodeConfigExt {
    async fn initialize_node_config(
        &mut self,
    ) -> Result<NodeConfig<IndexedDbBlockstore, IndexedDbStore>, JsError>;
}

impl WasmNodeConfigExt for WasmNodeConfig {
    async fn initialize_node_config(
        &mut self,
    ) -> Result<NodeConfig<IndexedDbBlockstore, IndexedDbStore>, JsError> {
        let network_id = network_id(self.network.into());

        // Initialize stores
        let store = IndexedDbStore::new(network_id)
            .await
            .map_err(|e| JsError::new(&format!("Failed to open the store: {}", e)))?;

        let blockstore = IndexedDbBlockstore::new(&format!("{network_id}-blockstore"))
            .await
            .map_err(|e| JsError::new(&format!("Failed to open the blockstore: {}", e)))?;

        if self.network == Network::Private {
            let bridge_addr = CelestiaConfig::fetch_bridge_webtransport_multiaddr().await;
            self.bootnodes = vec![bridge_addr.to_string()];
        }

        // Process bootnodes
        let mut p2p_bootnodes = Vec::with_capacity(self.bootnodes.len());

        for addr in &self.bootnodes {
            console::log_1(&format!("🚀 Adding bootnode: {}", addr).into());
            let addr = addr
                .parse()
                .map_err(|e| JsError::new(&format!("Invalid multiaddr '{}': {}", addr, e)))?;
            let resolved_addrs = resolve_dnsaddr_multiaddress(addr)
                .await
                .map_err(|e| JsError::new(&format!("Invalid multiaddr '{}'", e)))?;
            p2p_bootnodes.extend(resolved_addrs.into_iter());
        }

        Ok(NodeConfig {
            network_id: network_id.to_string(),
            p2p_bootnodes,
            p2p_local_keypair: Keypair::generate_ed25519(),
            p2p_listen_on: vec![],
            sync_batch_size: 128,
            custom_syncing_window: self
                .custom_syncing_window_secs
                .map(|d| Duration::from_secs(d.into())),
            blockstore,
            store,
        })
    }
}
