use serde::{Deserialize, Serialize};
use std::{self, fmt::Display};
use utoipa::ToSchema;

use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::raw_or_b64;

use prism_errors::OperationError;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
#[schema(
    title = "Operation",
    description = "State transition operation in the system",
    example = r#"{
        "RegisterService": {
            "id": "prism",
            "creation_gate": {
                "Signed": "pzK1LaZAJzxr9nfD5LIOYZxnk26eIOD74V8IS2ir05g"
            },
            "key": "DmzD4PQL-QuqbEmMd9lDpoGQOnU6eCJsGcyBNGL4GhQ"
        }
    }"#
)]
/// An [`Operation`] represents a state transition in the system.
/// In a blockchain analogy, this would be the full set of our transaction types.
pub enum Operation {
    #[schema(title = "CreateAccount")]
    /// Creates a new account with the given id and key.
    CreateAccount {
        /// Unique identifier for the account
        #[schema(example = "user123@prism.xyz")]
        id: String,
        /// Identifier of the service this account belongs to
        #[schema(example = "prism")]
        service_id: String,
        /// Challenge response required for account creation
        challenge: ServiceChallengeInput,
        /// Public key associated with the account
        key: VerifyingKey,
    },
    #[schema(title = "RegisterService")]
    /// Registers a new service with the given id.
    RegisterService {
        /// Unique identifier for the service
        #[schema(example = "prism")]
        id: String,
        /// Creation gate that defines how accounts can be created for this service
        creation_gate: ServiceChallenge,
        /// Public key associated with the service
        key: VerifyingKey,
    },
    #[schema(title = "AddData")]
    /// Adds arbitrary signed data to an existing account.
    AddData {
        /// Raw data to be added to the account
        #[serde(with = "raw_or_b64")]
        #[schema(example = "dGVzdDEyMzQ=")]
        data: Vec<u8>,
        /// Bundle containing signature of the data and verification key
        data_signature: SignatureBundle,
    },
    #[schema(title = "SetData")]
    /// Set arbitrary signed data to an existing account. Replaces all existing data.
    SetData {
        /// Raw data to replace existing account data
        #[serde(with = "raw_or_b64")]
        #[schema(example = "eWFvbWluZzEyMw==")]
        data: Vec<u8>,
        /// Bundle containing signature of the data and verification key
        data_signature: SignatureBundle,
    },
    #[schema(title = "AddKey")]
    /// Adds a key to an existing account.
    AddKey {
        /// Public key to be added to the account
        key: VerifyingKey,
    },
    #[schema(title = "RevokeKey")]
    /// Revokes a key from an existing account.
    RevokeKey {
        /// Public key to be revoked from the account
        key: VerifyingKey,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// Represents a signature and the key to verify it.
pub struct SignatureBundle {
    /// The key that can be used to verify the signature
    pub verifying_key: VerifyingKey,
    /// The actual signature
    pub signature: Signature,
}

impl SignatureBundle {
    /// Creates a new `SignatureBundle` with the given verifying key and signature.
    pub fn new(verifying_key: VerifyingKey, signature: Signature) -> Self {
        SignatureBundle {
            verifying_key,
            signature,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// Input required to complete a challenge for account creation.
pub enum ServiceChallengeInput {
    /// Input required when meeting `ServiceChallenge::Signed`.
    /// The provided signature will be verified using the corresponding key from the challenge.
    #[schema(title = "Signed")]
    Signed(Signature),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// A challenge that must be met with valid corresponding `ServiceChallengeInput`
/// when creating an account.
pub enum ServiceChallenge {
    /// Challenge that requires the service to sign corresponding CreateAccount operations
    /// such that the given key can be used to verify their signatures.
    #[schema(title = "Signed")]
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

    pub fn validate_basic(&self) -> Result<(), OperationError> {
        match &self {
            Operation::RegisterService { id, .. } => {
                if id.is_empty() {
                    return Err(OperationError::EmptyServiceId);
                }

                Ok(())
            }
            Operation::CreateAccount { id, service_id, .. } => {
                if id.is_empty() {
                    return Err(OperationError::EmptyAccountId);
                }

                if service_id.is_empty() {
                    return Err(OperationError::EmptyServiceIdForAccount);
                }

                Ok(())
            }
            Operation::AddKey { .. } | Operation::RevokeKey { .. } => Ok(()),
            Operation::AddData { data, .. } | Operation::SetData { data, .. } => {
                let data_len = data.len();
                // TODO determine proper max data size here
                const MAX_DATA_SIZE: usize = 1_000_000; // 1MB limit for now
                if data_len >= MAX_DATA_SIZE {
                    return Err(OperationError::DataTooLarge(data_len));
                }
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
