use anyhow::{Context, Result};
use celestia_types::Blob;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
// An [`Operation`] represents a state transition in the system.
// In a blockchain analogy, this would be the full set of our transaction types.
pub enum Operation {
    // Creates a new account with the given id and value.
    CreateAccount {
        id: String,
        value: String,
        source: AccountSource,
    },
    // Adds a value to an existing account.
    Add {
        id: String,
        value: String,
    },
    // Revokes a value from an existing account.
    Revoke {
        id: String,
        value: String,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
// An [`AccountSource`] represents the source of an account. See adr-002 for more information.
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

impl TryFrom<&Blob> for Operation {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        bincode::deserialize(&value.data)
            .context(format!("Failed to decode blob into Operation: {value:?}"))
    }
}
