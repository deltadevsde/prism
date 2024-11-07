use anyhow::anyhow;
use celestia_types::Blob;
use serde::{Deserialize, Serialize};

use crate::hashchain::HashchainEntry;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PendingRequest {
    pub id: String,
    pub entry: HashchainEntry,
}

pub trait RequestLike {
    fn id(&self) -> &str;
    fn entry(&self) -> &HashchainEntry;
}

impl<T: RequestLike> From<T> for PendingRequest {
    fn from(data: T) -> Self {
        PendingRequest {
            id: data.id().to_string(),
            entry: data.entry().clone(),
        }
    }
}

impl TryFrom<&Blob> for PendingRequest {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        bincode::deserialize(&value.data)
            .map_err(|e| anyhow!("Failed to decode blob into Operation: error: {}", e))
    }
}
