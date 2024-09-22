use anyhow::{Context, Result};
use bincode;
use celestia_types::Blob;
use ed25519_dalek::{Signer, SigningKey};
use prism_errors::GeneralError;
use serde::{Deserialize, Serialize};
use std::{self, fmt::Display};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
/// Represents a public key supported by the system.
pub enum PublicKey {
    // Secp256k1(Vec<u8>),  // Bitcoin, Ethereum
    // Curve25519(Vec<u8>), // Signal, Tor
    Ed25519(Vec<u8>), // Cosmos, OpenSSH, GnuPG
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(bytes) => bytes,
            // PublicKey::Secp256k1(bytes) => bytes,
            // PublicKey::Curve25519(bytes) => bytes,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Represents a signature bundle, which includes the index of the key
/// in the user's hashchain and the associated signature.
pub struct SignatureBundle {
    pub key_idx: u64,       // Index of the key in the hashchain
    pub signature: Vec<u8>, // The actual signature
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Input required to complete a challenge for account creation.
pub enum ServiceChallengeInput {
    Signed(Vec<u8>), // Signature bytes
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
// An [`Operation`] represents a state transition in the system.
// In a blockchain analogy, this would be the full set of our transaction types.
pub enum Operation {
    // Creates a new account with the given id and value.
    CreateAccount(CreateAccountArgs),
    // Adds a value to an existing account.
    AddKey(KeyOperationArgs),
    // Revokes a value from an existing account.
    RevokeKey(KeyOperationArgs),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Arguments for creating an account with a service.
pub struct CreateAccountArgs {
    pub id: String,       // Account ID
    pub value: PublicKey, // Public Key
    pub signature: Vec<u8>,
    pub service_id: String,               // Associated service ID
    pub challenge: ServiceChallengeInput, // Challenge input for verification
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Common structure for operations involving keys (adding or revoking).
pub struct KeyOperationArgs {
    pub id: String,                 // Account ID
    pub value: PublicKey,           // Public key being added or revoked
    pub signature: SignatureBundle, // Signature to authorize the action
}

impl Operation {
    pub fn id(&self) -> String {
        match self {
            Operation::CreateAccount(args) => args.id.clone(),
            Operation::AddKey(args) => args.id.clone(),
            Operation::RevokeKey(args) => args.id.clone(),
        }
    }

    pub fn get_public_key(&self) -> Option<PublicKey> {
        match self {
            Operation::AddKey(args) => Some(args.value.clone()),
            Operation::RevokeKey(args) => Some(args.value.clone()),
            Operation::CreateAccount(args) => Some(args.value.clone()),
        }
    }

    pub fn get_signature_bundle(&self) -> Option<SignatureBundle> {
        match self {
            Operation::AddKey(args) => Some(args.signature.clone()),
            Operation::RevokeKey(args) => Some(args.signature.clone()),
            Operation::CreateAccount(args) => Some(SignatureBundle {
                key_idx: 0,
                signature: args.signature.clone(),
            }),
        }
    }

    pub fn insert_signature(&mut self, signing_key: &SigningKey) -> Result<()> {
        let serialized = bincode::serialize(self).context("Failed to serialize operation")?;
        let signature = signing_key.sign(&serialized);

        match self {
            Operation::CreateAccount(args) => args.signature = signature.to_bytes().to_vec(),
            Operation::AddKey(args) | Operation::RevokeKey(args) => {
                args.signature.signature = signature.to_bytes().to_vec()
            }
        }
        Ok(())
    }

    pub fn without_signature(&self) -> Self {
        match self {
            Operation::AddKey(args) => Operation::AddKey(KeyOperationArgs {
                id: args.id.clone(),
                value: args.value.clone(),
                signature: SignatureBundle {
                    key_idx: args.signature.key_idx,
                    signature: Vec::new(),
                },
            }),
            Operation::RevokeKey(args) => Operation::RevokeKey(KeyOperationArgs {
                id: args.id.clone(),
                value: args.value.clone(),
                signature: SignatureBundle {
                    key_idx: args.signature.key_idx,
                    signature: Vec::new(),
                },
            }),
            Operation::CreateAccount(args) => Operation::CreateAccount(CreateAccountArgs {
                id: args.id.clone(),
                value: args.value.clone(),
                signature: Vec::new(),
                service_id: args.service_id.clone(),
                challenge: args.challenge.clone(),
            }),
        }
    }

    pub fn validate(&self) -> Result<()> {
        match &self {
            Operation::AddKey(KeyOperationArgs { id, signature, .. })
            | Operation::RevokeKey(KeyOperationArgs { id, signature, .. }) => {
                if id.is_empty() {
                    return Err(
                        GeneralError::MissingArgumentError("id is empty".to_string()).into(),
                    );
                }

                if signature.signature.is_empty() {
                    return Err(GeneralError::MissingArgumentError(
                        "signature is empty".to_string(),
                    )
                    .into());
                }

                Ok(())
            }
            Operation::CreateAccount(CreateAccountArgs { id, .. }) => {
                if id.is_empty() {
                    return Err(
                        GeneralError::MissingArgumentError("id is empty".to_string()).into(),
                    );
                }

                // match challenge {
                //     ServiceChallengeInput::Signed(signature) => {
                //         if signature.is_empty() {
                //             return Err(GeneralError::MissingArgumentError(
                //                 "challenge data is empty".to_string(),
                //             )
                //             .into());
                //         }
                //     }
                // }

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

impl TryFrom<&Blob> for Operation {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        bincode::deserialize(&value.data)
            .context(format!("Failed to decode blob into Operation: {value:?}"))
    }
}
