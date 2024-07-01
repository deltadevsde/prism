use async_trait::async_trait;
use base64::engine::{general_purpose, Engine as _};
use ed25519::Signature;
use indexed_merkle_tree::tree::Proof;
use mockall::predicate::*;
use mockall::*;
use serde::{Deserialize, Serialize};
use std::{self, fmt::Display};
pub mod indexeddb;
pub mod redis;

use crate::error::{DatabaseError, DeimosError, GeneralError};
use crate::utils::Signable;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Operation {
    Add,
    Revoke,
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Operation::Add => write!(f, "Add"),
            Operation::Revoke => write!(f, "Revoke"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ChainEntry {
    pub hash: String,
    pub previous_hash: String,
    pub operation: Operation,
    pub value: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Entry {
    pub id: String,
    pub value: Vec<ChainEntry>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DerivedEntry {
    pub id: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingEntry {
    pub id: String,
    pub operation: Operation,
    pub value: String,
}

#[derive(Deserialize, Debug)]
pub struct UpdateEntryJson {
    pub id: String,
    pub signed_message: String,
    pub public_key: String,
}

fn decode_signed_message(signed_message: &String) -> Result<Vec<u8>, DeimosError> {
    let signed_message_bytes = general_purpose::STANDARD
        .decode(&signed_message)
        .map_err(|_| {
            DeimosError::General(GeneralError::DecodingError(
                "failed to decode signed message".to_string(),
            ))
        })?;

    // check if the signed message is (at least) 64 bytes long
    if signed_message_bytes.len() < 64 {
        return Err(DeimosError::General(GeneralError::ParsingError(
            "signed message is too short".to_string(),
        )));
    } else {
        Ok(signed_message_bytes)
    }
}

impl Signable for UpdateEntryJson {
    fn get_signature(&self) -> Result<Signature, DeimosError> {
        let signed_message_bytes = decode_signed_message(&self.signed_message)?;

        // extract the first 64 bytes from the signed message which are the signature
        let signature_bytes: &[u8; 64] = match signed_message_bytes.get(..64) {
            Some(array_section) => match array_section.try_into() {
                Ok(array) => array,
                Err(_) => Err(DeimosError::General(GeneralError::ParsingError(
                    "failed to convert signed message to array".to_string(),
                )))?,
            },
            None => Err(DeimosError::General(GeneralError::ParsingError(
                "failed to extract signature from signed message".to_string(),
            )))?,
        };

        Ok(Signature::from_bytes(signature_bytes))
    }

    fn get_content_to_sign(&self) -> Result<String, DeimosError> {
        let signed_message_bytes = decode_signed_message(&self.signed_message)?;
        let message_bytes = &signed_message_bytes[64..];
        Ok(String::from_utf8_lossy(message_bytes).to_string())
    }

    fn get_public_key(&self) -> Result<String, DeimosError> {
        Ok(self.public_key.clone())
    }
}

#[automock]
#[async_trait]
pub trait Database: Send + Sync {
    async fn get_keys(&self) -> Result<Vec<String>, DatabaseError>;
    async fn get_derived_keys(&self) -> Result<Vec<String>, DatabaseError>;
    async fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, DeimosError>;
    async fn get_derived_value(&self, key: &String) -> Result<String, DatabaseError>;
    async fn get_derived_keys_in_order(&self) -> Result<Vec<String>, DatabaseError>;
    async fn get_commitment(&self, epoch: &u64) -> Result<String, DatabaseError>;
    async fn get_proof(&self, id: &String) -> Result<String, DatabaseError>;
    async fn get_proofs_in_epoch(&self, epoch: &u64) -> Result<Vec<Proof>, DatabaseError>;
    async fn get_epoch(&self) -> Result<u64, DatabaseError>;
    async fn get_epoch_operation(&self) -> Result<u64, DatabaseError>;
    async fn set_epoch(&self, epoch: &u64) -> Result<(), DatabaseError>;
    async fn reset_epoch_operation_counter(&self) -> Result<(), DatabaseError>;
    async fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &Vec<ChainEntry>,
    ) -> Result<(), DeimosError>;
    async fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> Result<(), DatabaseError>;
    async fn get_epochs(&self) -> Result<Vec<u64>, DeimosError>;
    async fn increment_epoch_operation(&self) -> Result<u64, DatabaseError>;
    async fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &String,
        proofs: &String,
    ) -> Result<(), DatabaseError>;
    async fn add_commitment(&self, epoch: &u64, commitment: &String) -> Result<(), DatabaseError>;
    async fn initialize_derived_dict(&self) -> Result<(), DatabaseError>;
    async fn flush_database(&self) -> Result<(), DatabaseError>;
}
