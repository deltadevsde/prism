use anyhow::{bail, ensure, Result};

use serde::{Deserialize, Serialize};
use std::{self, fmt::Display};
use utoipa::ToSchema;

use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::raw_or_b64;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// An [`Operation`] represents a state transition in the system.
/// In a blockchain analogy, this would be the full set of our transaction types.
pub enum Operation {
    /// Creates a new account with the given id and key.
    CreateAccount {
        id: String,
        service_id: String,
        challenge: ServiceChallengeInput,
        key: VerifyingKey,
    },
    /// Registers a new service with the given id.
    RegisterService {
        id: String,
        creation_gate: ServiceChallenge,
        key: VerifyingKey,
    },
    /// Adds arbitrary signed data to an existing account.
    AddData {
        #[serde(with = "raw_or_b64")]
        data: Vec<u8>,
        data_signature: SignatureBundle,
    },
    /// Set arbitrary signed data to an existing account. Replaces all existing data.
    SetData {
        #[serde(with = "raw_or_b64")]
        data: Vec<u8>,
        data_signature: SignatureBundle,
    },
    /// Adds a key to an existing account.
    AddKey { key: VerifyingKey },
    /// Revokes a key from an existing account.
    RevokeKey { key: VerifyingKey },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// Represents a signature and the key to verify it.
pub struct SignatureBundle {
    /// The key that can be used to verify the signature
    pub verifying_key: VerifyingKey,
    /// The actual signature
    pub signature: Signature,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// Input required to complete a challenge for account creation.
pub enum ServiceChallengeInput {
    /// Signature bytes
    Signed(Signature),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
pub enum ServiceChallenge {
    Signed(VerifyingKey),
}

impl From<SigningKey> for ServiceChallenge {
    fn from(sk: SigningKey) -> Self {
        ServiceChallenge::Signed(sk.into())
    }
}

impl Operation {
    pub fn get_public_key(&self) -> Option<&VerifyingKey> {
        match self {
            Operation::RevokeKey { key }
            | Operation::AddKey { key }
            | Operation::CreateAccount { key, .. }
            | Operation::RegisterService { key, .. } => Some(key),
            Operation::AddData { .. } | Operation::SetData { .. } => None,
        }
    }

    pub fn validate_basic(&self) -> Result<()> {
        match &self {
            Operation::RegisterService { id, .. } => {
                if id.is_empty() {
                    bail!("id must not be empty when registering service");
                }

                Ok(())
            }
            Operation::CreateAccount { id, service_id, .. } => {
                if id.is_empty() {
                    bail!("id must not be empty when creating account service");
                }

                if service_id.is_empty() {
                    bail!("service_id must not be empty when creating account service");
                }

                Ok(())
            }
            Operation::AddKey { .. } | Operation::RevokeKey { .. } => Ok(()),
            Operation::AddData { data, .. } | Operation::SetData { data, .. } => {
                let data_len = data.len();
                // TODO determine proper max data size here
                ensure!(data_len < usize::MAX, "Incoming data size is {}", data_len);
                Ok(())
            }
        }
    }
}

impl Display for Operation {
    // just print the debug
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
