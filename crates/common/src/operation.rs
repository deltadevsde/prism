use anyhow::{Context, Result};
use bincode;
use celestia_types::Blob;
use prism_errors::GeneralError;
use serde::{Deserialize, Serialize};
use std::{self, fmt::Display};

use crate::{
    digest::Digest,
    keys::{SigningKey, VerifyingKey},
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// An [`Operation`] represents a state transition in the system.
/// In a blockchain analogy, this would be the full set of our transaction types.
pub enum Operation {
    /// Creates a new account with the given id and value.
    CreateAccount(CreateAccountArgs),
    /// Adds a key to an existing account.
    AddKey(KeyOperationArgs),
    /// Adds arbitrary signed data to an existing account.
    AddData(AddDataArgs),
    /// Revokes a key from an existing account.
    RevokeKey(KeyOperationArgs),
    /// Registers a new service with the given id.
    RegisterService(RegisterServiceArgs),
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
/// Represents a signature bundle, which includes the index of the key
/// in the user's hashchain and the associated signature.
pub struct HashchainSignatureBundle {
    /// Index of the key in the hashchain
    pub key_idx: usize,
    /// The actual signature
    pub signature: Vec<u8>,
}

impl HashchainSignatureBundle {
    pub fn empty_with_idx(idx: usize) -> Self {
        HashchainSignatureBundle {
            key_idx: idx,
            signature: vec![],
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Represents a signature including its.
pub struct SignatureBundle {
    /// The key that can be used to verify the signature
    pub verifying_key: VerifyingKey,
    /// The actual signature
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Input required to complete a challenge for account creation.
pub enum ServiceChallengeInput {
    /// Signature bytes
    Signed(Vec<u8>),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Arguments for creating an account with a service.
pub struct CreateAccountArgs {
    /// Account ID
    pub id: String,
    /// Public key being added
    pub value: VerifyingKey,
    /// Associated service ID
    pub service_id: String,
    /// Challenge input for verification
    pub challenge: ServiceChallengeInput,
    /// The hash of the previous operation
    pub prev_hash: Digest,
    /// The signature that signed the operation
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Arguments for registering a new service.
pub struct RegisterServiceArgs {
    /// Service ID
    pub id: String,
    /// Challenge gate for access control
    pub creation_gate: ServiceChallenge,
    /// The hash of the previous operation
    pub prev_hash: Digest,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum ServiceChallenge {
    Signed(VerifyingKey),
}

impl From<SigningKey> for ServiceChallenge {
    fn from(sk: SigningKey) -> Self {
        ServiceChallenge::Signed(sk.into())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Structure for adding data.
pub struct AddDataArgs {
    /// Account ID
    pub id: String,
    /// Data to be added
    pub value: Vec<u8>,
    /// Optional external signature used to sign the data to be added
    pub value_signature: Option<SignatureBundle>,
    /// The hash of the previous operation
    pub prev_hash: Digest,
    /// Signature to authorize the action
    pub op_signature: HashchainSignatureBundle,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Common structure for operations involving keys (adding or revoking).
pub struct KeyOperationArgs {
    /// Account ID
    pub id: String,
    /// Public key being added or revoked
    pub value: VerifyingKey,
    /// The hash of the previous operation
    pub prev_hash: Digest,
    /// Signature to authorize the action
    pub signature: HashchainSignatureBundle,
}

impl Operation {
    pub fn new_create_account(
        id: String,
        signing_key: &SigningKey,
        service_id: String,
        service_signer: &SigningKey,
    ) -> Result<Self> {
        let mut op = Operation::CreateAccount(CreateAccountArgs {
            id: id.to_string(),
            value: signing_key.clone().into(),
            service_id,
            challenge: ServiceChallengeInput::Signed(Vec::new()),
            prev_hash: Digest::zero(),
            signature: Vec::new(),
        });

        op.insert_signature(signing_key)
            .expect("Inserting signature into operation should succeed");

        let msg = bincode::serialize(&op).unwrap();
        let service_challenge = service_signer.sign(&msg);

        match op {
            Operation::CreateAccount(ref mut args) => {
                args.challenge = ServiceChallengeInput::Signed(service_challenge);
            }
            _ => panic!("Operation should be CreateAccount"),
        };
        Ok(op)
    }

    pub fn new_register_service(id: String, creation_gate: ServiceChallenge) -> Self {
        Operation::RegisterService(RegisterServiceArgs {
            id,
            creation_gate,
            prev_hash: Digest::zero(),
        })
    }

    pub fn new_add_key(
        id: String,
        value: VerifyingKey,
        prev_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Result<Self> {
        let op_to_sign = Operation::AddKey(KeyOperationArgs {
            id: id.clone(),
            value: value.clone(),
            prev_hash,
            signature: HashchainSignatureBundle::empty_with_idx(key_idx),
        });

        let message = bincode::serialize(&op_to_sign)?;
        let signature = HashchainSignatureBundle {
            key_idx,
            signature: signing_key.sign(&message).to_vec(),
        };

        Ok(Operation::AddKey(KeyOperationArgs {
            id,
            value,
            prev_hash,
            signature,
        }))
    }

    pub fn new_revoke_key(
        id: String,
        value: VerifyingKey,
        prev_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Result<Self> {
        let op_to_sign = Operation::RevokeKey(KeyOperationArgs {
            id: id.clone(),
            value: value.clone(),
            prev_hash,
            signature: HashchainSignatureBundle::empty_with_idx(key_idx),
        });

        let message = bincode::serialize(&op_to_sign)?;
        let signature = HashchainSignatureBundle {
            key_idx,
            signature: signing_key.sign(&message).to_vec(),
        };

        Ok(Operation::RevokeKey(KeyOperationArgs {
            id,
            value,
            prev_hash,
            signature,
        }))
    }

    pub fn new_add_signed_data(
        id: String,
        value: Vec<u8>,
        value_signature: Option<SignatureBundle>,
        prev_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Result<Self> {
        let op_to_sign = Operation::AddData(AddDataArgs {
            id: id.clone(),
            value: value.clone(),
            value_signature: value_signature.clone(),
            prev_hash,
            op_signature: HashchainSignatureBundle::empty_with_idx(key_idx),
        });

        let message = { bincode::serialize(&op_to_sign)? };
        let op_signature = HashchainSignatureBundle {
            key_idx,
            signature: signing_key.sign(&message).to_vec(),
        };

        Ok(Operation::AddData(AddDataArgs {
            id,
            value,
            value_signature,
            prev_hash,
            op_signature,
        }))
    }

    pub fn id(&self) -> String {
        match self {
            Operation::CreateAccount(args) => args.id.clone(),
            Operation::AddKey(args) | Operation::RevokeKey(args) => args.id.clone(),
            Operation::AddData(args) => args.id.clone(),
            Operation::RegisterService(args) => args.id.clone(),
        }
    }

    pub fn get_public_key(&self) -> Option<&VerifyingKey> {
        match self {
            Operation::RevokeKey(args) | Operation::AddKey(args) => Some(&args.value),
            Operation::CreateAccount(args) => Some(&args.value),
            Operation::RegisterService(_) | Operation::AddData(_) => None,
        }
    }

    pub fn insert_signature(&mut self, signing_key: &SigningKey) -> Result<()> {
        let serialized = bincode::serialize(self).context("Failed to serialize operation")?;
        let signature = signing_key.sign(&serialized);

        match self {
            Operation::CreateAccount(args) => args.signature = signature,
            Operation::AddKey(args) | Operation::RevokeKey(args) => {
                args.signature.signature = signature
            }
            _ => unimplemented!("RegisterService prover gating not yet implemented"),
        }
        Ok(())
    }

    pub fn without_challenge(&self) -> Self {
        match self {
            Operation::CreateAccount(args) => Operation::CreateAccount(CreateAccountArgs {
                id: args.id.clone(),
                value: args.value.clone(),
                service_id: args.service_id.clone(),
                challenge: ServiceChallengeInput::Signed(Vec::new()),
                prev_hash: args.prev_hash,
                signature: args.signature.clone(),
            }),
            _ => self.clone(),
        }
    }

    pub fn without_signature(&self) -> Self {
        match self {
            Operation::AddKey(args) => Operation::AddKey(KeyOperationArgs {
                id: args.id.clone(),
                value: args.value.clone(),
                prev_hash: args.prev_hash,
                signature: HashchainSignatureBundle {
                    key_idx: args.signature.key_idx,
                    signature: Vec::new(),
                },
            }),
            Operation::RevokeKey(args) => Operation::RevokeKey(KeyOperationArgs {
                id: args.id.clone(),
                value: args.value.clone(),
                prev_hash: args.prev_hash,
                signature: HashchainSignatureBundle {
                    key_idx: args.signature.key_idx,
                    signature: Vec::new(),
                },
            }),
            Operation::AddData(args) => Operation::AddData(AddDataArgs {
                id: args.id.clone(),
                value: args.value.clone(),
                prev_hash: args.prev_hash,
                value_signature: args.value_signature.clone(),
                op_signature: HashchainSignatureBundle {
                    key_idx: args.op_signature.key_idx,
                    signature: Vec::new(),
                },
            }),
            Operation::CreateAccount(args) => Operation::CreateAccount(CreateAccountArgs {
                id: args.id.clone(),
                value: args.value.clone(),
                service_id: args.service_id.clone(),
                challenge: args.challenge.clone(),
                prev_hash: args.prev_hash,
                signature: Vec::new(),
            }),
            Operation::RegisterService(args) => Operation::RegisterService(RegisterServiceArgs {
                id: args.id.clone(),
                creation_gate: args.creation_gate.clone(),
                prev_hash: args.prev_hash,
            }),
        }
    }

    pub fn verify_user_signature(&self, pubkey: &VerifyingKey) -> Result<()> {
        match self {
            Operation::RegisterService(_) => Ok(()),
            Operation::CreateAccount(args) => {
                let message = bincode::serialize(&self.without_signature().without_challenge())
                    .context("User signature failed")?;
                args.value.verify_signature(&message, &args.signature)
            }
            Operation::AddKey(args) | Operation::RevokeKey(args) => {
                let message = bincode::serialize(&self.without_signature())
                    .context("User signature failed")?;
                pubkey.verify_signature(&message, &args.signature.signature)
            }
            Operation::AddData(args) => {
                let message = bincode::serialize(&self.without_signature())
                    .context("Serializing operation failed")?;
                pubkey
                    .verify_signature(&message, &args.op_signature.signature)
                    .context("Verifying operation signature failed")?;

                let Some(value_signature) = &args.value_signature else {
                    return Ok(());
                };

                // If data to be added is signed, also validate its signature
                value_signature
                    .verifying_key
                    .verify_signature(&args.value, &value_signature.signature)
                    .context("Verifying value signature failed")
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        match &self {
            Operation::AddKey(KeyOperationArgs { id, signature, .. })
            | Operation::RevokeKey(KeyOperationArgs { id, signature, .. })
            | Operation::AddData(AddDataArgs {
                id,
                op_signature: signature,
                ..
            }) => {
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
            Operation::CreateAccount(CreateAccountArgs { id, challenge, .. }) => {
                if id.is_empty() {
                    return Err(
                        GeneralError::MissingArgumentError("id is empty".to_string()).into(),
                    );
                }

                match challenge {
                    ServiceChallengeInput::Signed(signature) => {
                        if signature.is_empty() {
                            return Err(GeneralError::MissingArgumentError(
                                "challenge data is empty".to_string(),
                            )
                            .into());
                        }
                    }
                }

                Ok(())
            }
            Operation::RegisterService(_) => Ok(()),
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
