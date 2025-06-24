use k256::ecdsa::VerifyingKey as Secp256k1VerifyingKey;
use prism_serde::{bech32::ToBech32, raw_or_b64};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::result::Result;
use thiserror::Error;

#[derive(Serialize, Deserialize)]
struct CosmosSignDoc {
    account_number: String,
    chain_id: String,
    fee: CosmosFee,
    memo: String,
    msgs: Vec<CosmosMessage>,
    sequence: String,
}

#[derive(Serialize, Deserialize)]
struct CosmosFee {
    amount: Vec<String>,
    gas: String,
}

#[derive(Serialize, Deserialize)]
struct CosmosMessage {
    #[serde(rename = "type")]
    msg_type: String,
    value: CosmosMessageValue,
}

#[derive(Serialize, Deserialize)]
struct CosmosMessageValue {
    #[serde(with = "raw_or_b64")]
    data: Vec<u8>,
    signer: String,
}

impl CosmosSignDoc {
    fn new(signer: String, data: Vec<u8>) -> CosmosSignDoc {
        CosmosSignDoc {
            chain_id: "".to_string(),
            account_number: "0".to_string(),
            sequence: "0".to_string(),
            fee: CosmosFee {
                gas: "0".to_string(),
                amount: vec![],
            },
            msgs: vec![CosmosMessage {
                msg_type: "sign/MsgSignData".to_string(),
                value: CosmosMessageValue { signer, data },
            }],
            memo: "".to_string(),
        }
    }
}

/// Hashes a message according to the Cosmos ADR-36 specification.
///
/// This function creates a standardized Cosmos sign doc from the provided message,
/// serializes it according to ADR-36 requirements, and returns its SHA256 hash.
///
/// # Arguments
/// * `message` - The message to be hashed, which can be any type that can be referenced as a byte slice
/// * `verifying_key` - The Secp256k1 verifying key associated with the signer
///
/// # Returns
/// * `Result<Vec<u8>>` - The SHA256 hash of the serialized sign doc or an error
pub fn cosmos_adr36_hash_message(
    message: impl AsRef<[u8]>,
    verifying_key: &Secp256k1VerifyingKey,
) -> Result<Vec<u8>, CosmosError> {
    // TODO: Support arbitrary address prefixes
    // At the moment we expect users to use "cosmoshub-4" as chainId when
    // signing prism data via `signArbitrary(..)`, resulting in "cosmos" as address prefix
    const ADDRESS_PREFIX: &str = "cosmos";

    let signer = signer_from_key(ADDRESS_PREFIX, verifying_key)?;
    let serialized_sign_doc = create_serialized_adr36_sign_doc(message.as_ref().to_vec(), signer)
        .map_err(|e| CosmosError::GeneralError(e.to_string()))?;
    let hashed_sign_doc = Sha256::digest(&serialized_sign_doc).to_vec();
    Ok(hashed_sign_doc)
}

/// Creates a serialized Cosmos ADR-36 sign document.
///
/// This function constructs a CosmosSignDoc with the provided data and signer,
/// serializes it to JSON, and escapes certain HTML special characters to comply
/// with ADR-36 requirements.
///
/// # Arguments
/// * `data` - The binary data to be included in the sign document
/// * `signer` - The bech32-encoded address of the signer
///
/// # Returns
/// * `Result<Vec<u8>>` - The serialized sign document as bytes or an error
fn create_serialized_adr36_sign_doc(data: Vec<u8>, signer: String) -> Result<Vec<u8>, CosmosError> {
    let adr36_sign_doc = CosmosSignDoc::new(signer, data);

    let sign_doc_str = serde_json::to_string(&adr36_sign_doc)
        .map_err(|e| CosmosError::GeneralError(e.to_string()))?
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026");
    Ok(sign_doc_str.into_bytes())
}

/// Derives a Cosmos bech32-encoded address from a Secp256k1 verifying key.
///
/// This follows the Cosmos address derivation process:
/// 1. Takes the SEC1-encoded public key bytes
/// 2. Computes SHA256 hash of those bytes
/// 3. Computes RIPEMD160 hash of the SHA256 result
/// 4. Encodes the resulting 20-byte hash with bech32 using the provided prefix
///
/// # Arguments
/// * `address_prefix` - The bech32 human-readable part (e.g., "cosmos")
/// * `verifying_key` - The Secp256k1 verifying key to derive the address from
///
/// # Returns
/// * `Result<String>` - The bech32-encoded address or an error
fn signer_from_key(
    address_prefix: &str,
    verifying_key: &Secp256k1VerifyingKey,
) -> Result<String, CosmosError> {
    let verifying_key_bytes = verifying_key.to_sec1_bytes();
    let hashed_key_bytes = Sha256::digest(verifying_key_bytes);
    let cosmos_address = Ripemd160::digest(hashed_key_bytes);

    let signer = cosmos_address
        .to_bech32(address_prefix)
        .map_err(|e| CosmosError::GeneralError(e.to_string()))?;
    Ok(signer)
}

#[derive(Error, Clone, Debug)]
pub enum CosmosError {
    #[error("something went wrong: {0}")]
    GeneralError(String),
}
