use celestia_types::Blob;
use prism_serde::binary::BinaryTranscodable;
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
        Transaction::decode_from_bytes(&value.data)
    }
}
