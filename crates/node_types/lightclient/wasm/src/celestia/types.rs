use anyhow::Context;
use celestia_types::Blob;
use serde::{Deserialize, Serialize};

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
