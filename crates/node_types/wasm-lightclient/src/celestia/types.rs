/* use std::str::FromStr;

use anyhow::Context;
use celestia_types::Blob;
use prism_cli::network::{Network, NetworkConfig};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FinalizedEpoch {
    pub height: u64,
    pub prev_commitment: [u8; 32],
    pub current_commitment: [u8; 32],
    pub proof: Vec<u8>,
    pub vk_hash: String,
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

#[wasm_bindgen]
pub struct VerifyEpochResult {
    pub verified: bool,
    pub height: u64,
}

#[wasm_bindgen]
impl VerifyEpochResult {
    pub fn new(verified: bool, height: u64) -> Self {
        Self { verified, height }
    }
}

#[wasm_bindgen]
pub struct WasmNetworkConfig(NetworkConfig);

#[wasm_bindgen]
impl WasmNetworkConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(network_name: Option<String>) -> Self {
        let network = Network::from_str(&network_name.unwrap_or_else(|| "custom".to_string()))
            .unwrap_or_else(|_| Network::Custom("custom".to_string()));

        WasmNetworkConfig(network.config())
    }

    #[wasm_bindgen(getter)]
    pub fn start_height(&self) -> u64 {
        self.0.celestia_config.as_ref().map(|cfg| cfg.start_height).unwrap_or(4279075)
    }

    #[wasm_bindgen(getter)]
    pub fn snark_namespace_id(&self) -> String {
        self.0.celestia_config.as_ref().map(|cfg| cfg.snark_namespace_id.clone()).unwrap_or_else(
            || "000000000000000000000000000000000000707269736d5350457330".to_string(),
        )
    }
}
 */
