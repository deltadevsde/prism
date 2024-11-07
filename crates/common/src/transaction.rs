use anyhow::anyhow;
use celestia_types::Blob;
use serde::{Deserialize, Serialize};

use crate::hashchain::HashchainEntry;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Transaction {
    pub id: String,
    pub entry: HashchainEntry,
}

impl TryFrom<&Blob> for Transaction {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        bincode::deserialize(&value.data)
            .map_err(|e| anyhow!("Failed to decode blob into Operation: error: {}", e))
    }
}
