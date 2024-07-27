use indexed_merkle_tree::Hash;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Operation {
    CreateAccount { id: String, value: String },
    Add { id: String, value: String },
    Revoke { id: String, value: String },
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::CreateAccount { id, value } => {
                write!(f, "CreateAccount {{ id: {}, value: {} }}", id, value)
            }
            Operation::Add { id, value } => write!(f, "Add {{ id: {}, value: {} }}", id, value),
            Operation::Revoke { id, value } => {
                write!(f, "Revoke {{ id: {}, value: {} }}", id, value)
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct HashchainEntry {
    pub hash: Hash,
    pub previous_hash: Hash,
    pub operation: Operation,
}
