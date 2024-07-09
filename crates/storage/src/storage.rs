use base64::engine::{general_purpose, Engine as _};
use ed25519::Signature;
use indexed_merkle_tree::{node::Node, sha256, tree::Proof};
use mockall::predicate::*;
use mockall::*;
use serde::{Deserialize, Serialize};
use std::{self, fmt::Display};

use crate::utils::Signable;
use crate::{
    error::{DatabaseError, DeimosError, DeimosResult, GeneralError},
    utils::parse_json_to_proof,
};

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

fn decode_signed_message(signed_message: &String) -> DeimosResult<Vec<u8>> {
    let signed_message_bytes = general_purpose::STANDARD
        .decode(&signed_message)
        .map_err(|e| {
            DeimosError::General(GeneralError::DecodingError(format!(
                "signed message: {}",
                e.to_string()
            )))
        })?;

    // check if the signed message is (at least) 64 bytes long
    if signed_message_bytes.len() < 64 {
        return Err(GeneralError::ParsingError(format!(
            "signed message is too short: {} < 64",
            signed_message_bytes.len(),
        ))
        .into());
    } else {
        Ok(signed_message_bytes)
    }
}

impl Signable for UpdateEntryJson {
    fn get_signature(&self) -> DeimosResult<Signature> {
        let signed_message_bytes = decode_signed_message(&self.signed_message)?;

        // extract the first 64 bytes from the signed message which are the signature
        let signature_bytes: &[u8; 64] = match signed_message_bytes.get(..64) {
            Some(array_section) => match array_section.try_into() {
                Ok(array) => array,
                Err(e) => Err(DeimosError::General(GeneralError::DecodingError(format!(
                    "signed message to array: {}",
                    e
                ))))?,
            },
            None => Err(DeimosError::General(GeneralError::DecodingError(format!(
                "extracting signature from signed message: {}",
                &self.signed_message
            ))))?,
        };

        Ok(Signature::from_bytes(signature_bytes))
    }

    fn get_content_to_sign(&self) -> DeimosResult<String> {
        let signed_message_bytes = decode_signed_message(&self.signed_message)?;
        let message_bytes = &signed_message_bytes[64..];
        Ok(String::from_utf8_lossy(message_bytes).to_string())
    }

    fn get_public_key(&self) -> DeimosResult<String> {
        Ok(self.public_key.clone())
    }
}

#[automock]
pub trait Database: Send + Sync {
    fn get_keys(&self) -> Result<Vec<String>, DatabaseError>;
    fn get_derived_keys(&self) -> Result<Vec<String>, DatabaseError>;
    fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, DatabaseError>;
    fn get_derived_value(&self, key: &String) -> Result<String, DatabaseError>;
    fn get_derived_keys_in_order(&self) -> Result<Vec<String>, DatabaseError>;
    fn get_commitment(&self, epoch: &u64) -> Result<String, DatabaseError>;
    fn get_proof(&self, id: &String) -> Result<String, DatabaseError>;
    fn get_proofs_in_epoch(&self, epoch: &u64) -> Result<Vec<Proof>, DatabaseError>;
    fn get_epoch(&self) -> Result<u64, DatabaseError>;
    fn get_epoch_operation(&self) -> Result<u64, DatabaseError>;
    fn set_epoch(&self, epoch: &u64) -> Result<(), DatabaseError>;
    fn reset_epoch_operation_counter(&self) -> Result<(), DatabaseError>;
    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &Vec<ChainEntry>,
    ) -> Result<(), DeimosError>;
    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> Result<(), DatabaseError>;
    fn get_epochs(&self) -> Result<Vec<u64>, DeimosError>;
    fn increment_epoch_operation(&self) -> Result<u64, DatabaseError>;
    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &String,
        proofs: &String,
    ) -> Result<(), DatabaseError>;
    fn add_commitment(&self, epoch: &u64, commitment: &String) -> Result<(), DatabaseError>;
    fn initialize_derived_dict(&self) -> Result<(), DatabaseError>;
    fn flush_database(&self) -> Result<(), DatabaseError>;
}
