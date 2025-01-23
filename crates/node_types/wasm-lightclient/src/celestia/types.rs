use anyhow::Context;
use celestia_types::Blob;
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
