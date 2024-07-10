use deimos_errors::errors::{DeimosError, DeimosResult, GeneralError};
use ed25519::Signature;
use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use ed25519_dalek::{Verifier, VerifyingKey as Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{self, fmt::Display, convert::TryInto};

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

pub trait Signable {
    fn get_signature(&self) -> DeimosResult<Signature>;
    fn get_content_to_sign(&self) -> DeimosResult<String>;
    fn get_public_key(&self) -> DeimosResult<String>;
}

// verifies the signature of a given signable item and returns the content of the item if the signature is valid
pub fn verify_signature<T: Signable>(
    item: &T,
    optional_public_key: Option<String>,
) -> DeimosResult<String> {
    let public_key_str = match optional_public_key {
        Some(key) => key,
        None => item.get_public_key()?,
    };

    let public_key = decode_public_key(&public_key_str)
        .map_err(|_| DeimosError::General(GeneralError::InvalidPublicKey))?;

    let content = item.get_content_to_sign()?;
    let signature = item.get_signature()?;

    if public_key.verify(content.as_bytes(), &signature).is_ok() {
        Ok(content)
    } else {
        Err(GeneralError::InvalidSignature.into())
    }
}

fn decode_signed_message(signed_message: &String) -> DeimosResult<Vec<u8>> {
    let signed_message_bytes = engine 
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
pub fn decode_public_key(pub_key_str: &String) -> DeimosResult<Ed25519VerifyingKey> {
    // decode the public key from base64 string to bytes
    let public_key_bytes = engine
        .decode(pub_key_str)
        .map_err(|e| GeneralError::DecodingError(format!("hex string: {}", e)))?;

    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| GeneralError::ParsingError("Vec<u8> to [u8; 32]".to_string()))?;

    Ed25519VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| GeneralError::DecodingError("ed25519 verifying key".to_string()).into())
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
