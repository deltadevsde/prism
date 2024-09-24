use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use bincode;
use celestia_types::Blob;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            PublicKey::Ed25519(bytes) => {
                if signature.len() != 64 {
                    return Err(anyhow!("Invalid signature length"));
                }

                let vk = VerifyingKey::from_bytes(bytes.as_slice().try_into()?)
                    .map_err(|e| anyhow!(e))?;
                let signature = Signature::from_bytes(signature.try_into()?);
                vk.verify_strict(message, &signature)
                    .map_err(|e| anyhow!(e))
            }
        }
    }
}

impl From<SigningKey> for PublicKey {
    fn from(sk: SigningKey) -> Self {
        PublicKey::Ed25519(sk.verifying_key().to_bytes().to_vec())
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(vk: VerifyingKey) -> Self {
        PublicKey::Ed25519(vk.to_bytes().to_vec())
    }
}

impl TryFrom<String> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        let bytes = engine
            .decode(&s)
            .map_err(|e| anyhow!("Failed to decode base64 string: {}", e))?;

        Ok(PublicKey::Ed25519(bytes.to_vec()))
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
/// Represents a signature bundle, which includes the index of the key
/// in the user's hashchain and the associated signature.
pub struct SignatureBundle {
    pub key_idx: u64,       // Index of the key in the hashchain
    pub signature: Vec<u8>, // The actual signature
}

impl SignatureBundle {
    pub fn empty_with_idx(idx: u64) -> Self {
        SignatureBundle {
            key_idx: idx,
            signature: vec![],
        }
    }
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
    // Registers a new service with the given id.
    RegisterService(RegisterServiceArgs),
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
/// Arguments for registering a new service.
pub struct RegisterServiceArgs {
    pub id: String,                      // Service ID
    pub creation_gate: ServiceChallenge, // Challenge gate for access control
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum ServiceChallenge {
    Signed(PublicKey),
}

impl From<SigningKey> for ServiceChallenge {
    fn from(sk: SigningKey) -> Self {
        ServiceChallenge::Signed(PublicKey::Ed25519(sk.verifying_key().as_bytes().to_vec()))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Common structure for operations involving keys (adding or revoking).
pub struct KeyOperationArgs {
    pub id: String,                 // Account ID
    pub value: PublicKey,           // Public key being added or revoked
    pub signature: SignatureBundle, // Signature to authorize the action
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
            value: signing_key.clone().verifying_key().into(),
            service_id,
            challenge: ServiceChallengeInput::Signed(Vec::new()),
            signature: Vec::new(),
        });

        op.insert_signature(signing_key)
            .expect("Inserting signature into operation should succeed");

        let msg = bincode::serialize(&op).unwrap();
        let service_challenge = service_signer.sign(&msg);

        match op {
            Operation::CreateAccount(ref mut args) => {
                args.challenge =
                    ServiceChallengeInput::Signed(service_challenge.to_bytes().to_vec());
            }
            _ => panic!("Operation should be CreateAccount"),
        };
        Ok(op)
    }

    pub fn new_register_service(id: String, creation_gate: ServiceChallenge) -> Self {
        Operation::RegisterService(RegisterServiceArgs { id, creation_gate })
    }

    pub fn new_add_key(
        id: String,
        value: PublicKey,
        signing_key: &SigningKey,
        key_idx: u64,
    ) -> Result<Self> {
        let op_to_sign = Operation::AddKey(KeyOperationArgs {
            id: id.clone(),
            value: value.clone(),
            signature: SignatureBundle::empty_with_idx(key_idx),
        });

        let message = bincode::serialize(&op_to_sign)?;
        let signature = SignatureBundle {
            key_idx,
            signature: signing_key.sign(&message).to_vec(),
        };

        Ok(Operation::AddKey(KeyOperationArgs {
            id,
            value,
            signature,
        }))
    }

    pub fn new_revoke_key(
        id: String,
        value: PublicKey,
        signing_key: &SigningKey,
        key_idx: u64,
    ) -> Result<Self> {
        let op_to_sign = Operation::RevokeKey(KeyOperationArgs {
            id: id.clone(),
            value: value.clone(),
            signature: SignatureBundle::empty_with_idx(key_idx),
        });

        let message = bincode::serialize(&op_to_sign)?;
        let signature = SignatureBundle {
            key_idx,
            signature: signing_key.sign(&message).to_vec(),
        };

        Ok(Operation::RevokeKey(KeyOperationArgs {
            id,
            value,
            signature,
        }))
    }

    pub fn id(&self) -> String {
        match self {
            Operation::CreateAccount(args) => args.id.clone(),
            Operation::AddKey(args) | Operation::RevokeKey(args) => args.id.clone(),
            Operation::RegisterService(args) => args.id.clone(),
        }
    }

    pub fn get_public_key(&self) -> Option<&PublicKey> {
        match self {
            Operation::RevokeKey(args) | Operation::AddKey(args) => Some(&args.value),
            Operation::CreateAccount(args) => Some(&args.value),
            Operation::RegisterService(_) => None,
        }
    }

    pub fn get_signature_bundle(&self) -> Option<SignatureBundle> {
        match self {
            Operation::AddKey(args) => Some(args.signature.clone()),
            Operation::RevokeKey(args) => Some(args.signature.clone()),
            Operation::RegisterService(_) | Operation::CreateAccount(_) => None,
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
            _ => unimplemented!("RegisterService sequencer gating not yet implemented"),
        }
        Ok(())
    }

    pub fn without_challenge(&self) -> Self {
        match self {
            Operation::CreateAccount(args) => Operation::CreateAccount(CreateAccountArgs {
                id: args.id.clone(),
                value: args.value.clone(),
                signature: args.signature.clone(),
                service_id: args.service_id.clone(),
                challenge: ServiceChallengeInput::Signed(Vec::new()),
            }),
            _ => self.clone(),
        }
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
            Operation::RegisterService(args) => Operation::RegisterService(RegisterServiceArgs {
                id: args.id.clone(),
                creation_gate: args.creation_gate.clone(),
            }),
        }
    }

    pub fn verify_user_signature(&self, pubkey: PublicKey) -> Result<()> {
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
