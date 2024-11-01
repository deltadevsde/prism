use anyhow::{anyhow, bail, Context, Result};
use bincode;
use celestia_types::Blob;
use serde::{Deserialize, Serialize};
use std::{self, fmt::Display};

use crate::{
    digest::Digest,
    keys::{SigningKey, VerifyingKey},
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// An [`Operation`] represents the data needed for a prism state transition.
pub struct Operation {
    /// The id of the account this operation is for.
    pub id: String,

    /// The operation variant.
    pub op: OperationType,

    /// The digest of the previous operation in the hashchain.
    pub prev_hash: Digest,

    pub new_key: Option<VerifyingKey>,
    pub signer_ref: Option<usize>,
    /// The signature of the operation.
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// An [`OperationType`] represents the type of operation being performed.
/// In a blockchain analogy, this would be the full set of our transaction types.
pub enum OperationType {
    /// Creates a new account with the given id and value.
    CreateAccount {
        service_id: String,
        challenge: ServiceChallengeInput,
    },
    /// Registers a new service with the given id.
    RegisterService { creation_gate: ServiceChallenge },
    /// Adds arbitrary signed data to an existing account.
    AddData {
        value: Vec<u8>,
        value_signature: Option<SignatureBundle>,
    },
    /// Adds a key to an existing account.
    AddKey,
    /// Revokes a key from an existing account.
    RevokeKey,
}

impl Operation {
    pub fn new_create_account(
        id: String,
        signing_key: &SigningKey,
        service_id: String,
        service_signer: &SigningKey,
    ) -> Result<Self> {
        let mut op = Operation::new(
            id.clone(),
            Digest::zero(),
            OperationType::CreateAccount {
                service_id: service_id.clone(),
                challenge: ServiceChallengeInput::Signed(Vec::new()),
            },
            Some(signing_key.verifying_key()),
            None,
        );

        op.insert_signature(signing_key).context("Failed to insert signature")?;

        let msg = bincode::serialize(&op).context("Failed to serialize operation")?;
        let service_challenge = service_signer.sign(&msg);

        op.op = OperationType::CreateAccount {
            service_id,
            challenge: ServiceChallengeInput::Signed(service_challenge),
        };

        Ok(op)
    }

    pub fn new_register_service(
        id: String,
        creation_gate: ServiceChallenge,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let mut op = Operation::new(
            id,
            Digest::zero(),
            OperationType::RegisterService { creation_gate },
            Some(signing_key.verifying_key()),
            None,
        );

        op.insert_signature(signing_key)?;

        Ok(op)
    }

    pub fn new_add_key(
        id: String,
        value: VerifyingKey,
        prev_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Result<Self> {
        let mut op = Operation::new(
            id,
            prev_hash,
            OperationType::AddKey,
            Some(value),
            Some(key_idx),
        );

        op.insert_signature(signing_key)?;

        Ok(op)
    }

    pub fn new_revoke_key(
        id: String,
        value: VerifyingKey,
        prev_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Result<Self> {
        let mut op = Operation::new(
            id,
            prev_hash,
            OperationType::RevokeKey,
            Some(value),
            Some(key_idx),
        );

        op.insert_signature(signing_key)?;

        Ok(op)
    }

    pub fn new_add_signed_data(
        id: String,
        value: Vec<u8>,
        value_signature: Option<SignatureBundle>,
        prev_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Result<Self> {
        let mut op = Operation::new(
            id,
            prev_hash,
            OperationType::AddData {
                value,
                value_signature,
            },
            None,
            Some(key_idx),
        );

        op.insert_signature(signing_key)?;

        Ok(op)
    }

    fn new(
        id: String,
        prev_hash: Digest,
        operation_type: OperationType,
        new_key: Option<VerifyingKey>,
        signer_ref: Option<usize>,
    ) -> Self {
        Operation {
            id,
            op: operation_type,
            prev_hash,
            new_key,
            signature: Vec::new(),
            signer_ref,
        }
    }

    pub fn get_public_key(&self) -> Option<&VerifyingKey> {
        return self.new_key.as_ref();
    }

    pub fn insert_signature(&mut self, signing_key: &SigningKey) -> Result<()> {
        let serialized = bincode::serialize(self).context("Failed to serialize operation")?;
        let signature = signing_key.sign(&serialized);

        self.signature = signature;
        Ok(())
    }

    pub fn without_challenge(&self) -> Self {
        let mut val = self.clone();
        if let OperationType::CreateAccount { service_id, .. } = &self.op {
            val.op = OperationType::CreateAccount {
                service_id: service_id.clone(),
                challenge: ServiceChallengeInput::Signed(Vec::new()),
            };
        }
        val
    }

    pub fn without_signature(&self) -> Self {
        let mut val = self.clone();
        val.signature = Vec::new();
        val
    }

    /// Validates the operation signature using the hashchain key (referenced
    /// either by index or first-op key)
    pub fn validate_signature(&self, pubkey: &VerifyingKey) -> Result<()> {
        let message = bincode::serialize(&self.without_signature().without_challenge())
            .context("User signature failed")?;
        pubkey.verify_signature(&message, &self.signature)?;

        match &self.op {
            OperationType::CreateAccount { .. } | OperationType::RegisterService { .. } => {
                let new_key = self.get_public_key().ok_or_else(|| anyhow!("No key supplied"))?;
                assert_eq!(new_key, pubkey);
                Ok(())
            }
            OperationType::AddData {
                value,
                value_signature,
            } => {
                let Some(value_signature) = &value_signature else {
                    return Ok(());
                };

                // If data to be added is signed, also validate its signature
                value_signature
                    .verifying_key
                    .verify_signature(value, &value_signature.signature)
                    .context("Verifying value signature failed")
            }
            _ => Ok(()),
        }
    }

    /// Does basic input validation, making sure that all required fields are present.
    /// Does not validate any signatures.
    pub fn validate_basic(&self) -> Result<()> {
        if self.id.is_empty() {
            bail!("Id is empty")
        }

        if self.signature.is_empty() {
            bail!("Signature is empty")
        }

        match &self.op {
            OperationType::AddKey | OperationType::RevokeKey => (),
            OperationType::RegisterService { .. } => {
                if self.new_key.is_none() {
                    bail!("Creating a hashchain requires adding an initial key");
                }
            }
            OperationType::AddData {
                value,
                value_signature,
            } => {
                // TODO: Upper bound on value size
                if value.is_empty() {
                    bail!("Adding external data requires a non-empty value");
                }

                if let Some(value_signature) = value_signature {
                    if value_signature.signature.is_empty() {
                        bail!("external data requires a non-empty signature")
                    }
                }
            }
            OperationType::CreateAccount { challenge, .. } => {
                if self.new_key.is_none() {
                    bail!("creating a hashchain requires adding an initial key");
                }

                match challenge {
                    ServiceChallengeInput::Signed(signature) => {
                        if signature.is_empty() {
                            bail!("account creation challenge is empty")
                        }
                    }
                }
            }
        };
        Ok(())
    }
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
pub enum ServiceChallenge {
    Signed(VerifyingKey),
}

impl From<SigningKey> for ServiceChallenge {
    fn from(sk: SigningKey) -> Self {
        ServiceChallenge::Signed(sk.verifying_key())
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
