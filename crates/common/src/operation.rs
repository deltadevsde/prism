use anyhow::{bail, ensure, Result};

use serde::{Deserialize, Serialize};
use std::{self, fmt::Display};

use crate::keys::{Signature, SigningKey, VerifyingKey};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
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
        data: Vec<u8>,
        data_signature: Option<SignatureBundle>,
    },
    /// Adds a key to an existing account.
    AddKey { key: VerifyingKey },
    /// Revokes a key from an existing account.
    RevokeKey { key: VerifyingKey },
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
/// Represents a signature bundle, which includes the index of the key
/// in the user's hashchain and the associated signature.
pub struct HashchainSignatureBundle {
    /// Index of the key in the hashchain
    pub key_idx: usize,
    /// The actual signature
    pub signature: Signature,
}

impl HashchainSignatureBundle {
    pub fn empty_with_idx(idx: usize) -> Self {
        HashchainSignatureBundle {
            key_idx: idx,
            signature: Signature::Placeholder,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Represents a signature including its.
pub struct SignatureBundle {
    /// The key that can be used to verify the signature
    pub verifying_key: VerifyingKey,
    /// The actual signature
    pub signature: Signature,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Input required to complete a challenge for account creation.
pub enum ServiceChallengeInput {
    /// Signature bytes
    Signed(Signature),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum ServiceChallenge {
    Signed(VerifyingKey),
}

impl From<SigningKey> for ServiceChallenge {
    fn from(sk: SigningKey) -> Self {
        ServiceChallenge::Signed(sk.verifying_key())
    }
}

impl Operation {
    pub fn get_public_key(&self) -> Option<&VerifyingKey> {
        match self {
            Operation::RevokeKey { key }
            | Operation::AddKey { key }
            | Operation::CreateAccount { key, .. }
            | Operation::RegisterService { key, .. } => Some(key),
            Operation::AddData { .. } => None,
        }
    }

    pub fn without_challenge(&self) -> Self {
        let Operation::CreateAccount {
            id,
            service_id,
            key,
            ..
        } = self
        else {
            return self.clone();
        };

        Operation::CreateAccount {
            id: id.clone(),
            service_id: service_id.clone(),
            key: key.clone(),
            challenge: ServiceChallengeInput::Signed(Signature::Placeholder),
        }
    }

    pub fn validate_basic(&self) -> Result<()> {
        match &self {
            Operation::RegisterService { .. } => Ok(()),
            Operation::CreateAccount { service_id, .. } => {
                if service_id.is_empty() {
                    bail!("service_id must not be empty when adding service");
                }

                Ok(())
            }
            Operation::AddKey { .. } | Operation::RevokeKey { .. } => Ok(()),
            Operation::AddData { data, .. } => {
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
