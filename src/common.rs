use indexed_merkle_tree::{sha256_mod, Hash};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Operation {
    CreateAccount {
        id: String,
        value: String,
        source: AccountSource,
    },
    Add {
        id: String,
        value: String,
    },
    Revoke {
        id: String,
        value: String,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum AccountSource {
    SignedBySequencer { signature: String },
}

impl Operation {
    pub fn id(&self) -> String {
        match self {
            Operation::CreateAccount { id, .. } => id.clone(),
            Operation::Add { id, .. } => id.clone(),
            Operation::Revoke { id, .. } => id.clone(),
        }
    }

    pub fn value(&self) -> String {
        match self {
            Operation::CreateAccount { value, .. } => value.clone(),
            Operation::Add { value, .. } => value.clone(),
            Operation::Revoke { value, .. } => value.clone(),
        }
    }
}

impl Display for Operation {
    // just print the debug
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct HashchainEntry {
    pub hash: Hash,
    pub previous_hash: Hash,
    pub operation: Operation,
}

impl HashchainEntry {
    pub fn new(operation: Operation, previous_hash: Hash) -> Self {
        let hash = {
            let mut data = Vec::new();
            data.extend_from_slice(operation.to_string().as_bytes());
            data.extend_from_slice(previous_hash.as_ref());
            sha256_mod(&data)
        };
        Self {
            hash,
            previous_hash,
            operation,
        }
    }
}
