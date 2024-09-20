use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use ed25519_consensus::Signature;
use ed25519_consensus::VerificationKey;
use ed25519_consensus::VerificationKeyBytes;
use prism_errors::{GeneralError, PrismError};

pub trait SignedContent {
    fn get_signature(&self) -> Result<Signature>;
    fn get_plaintext(&self) -> Result<Vec<u8>>;
    fn get_public_key(&self) -> Result<String>;
}

pub fn decode_public_key(pub_key_str: &String) -> Result<VerificationKey> {
    // decode the public key from base64 string to bytes
    let public_key_bytes = engine
        .decode(pub_key_str)
        .map_err(|e| GeneralError::DecodingError(format!("base64 string: {}", e)))?;

    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| GeneralError::ParsingError("Vec<u8> to [u8; 32]".to_string()))?;

    VerificationKeyBytes::try_from(public_key_array)
        .map_err(|_| GeneralError::DecodingError("ed25519 verifying key bytes".to_string()))?
        .try_into()
        .map_err(|_| GeneralError::DecodingError("ed25519 verifying key".to_string()).into())
}

// verifies the signature of a given signable item and returns the content of the item if the signature is valid
pub fn verify_signature<T: SignedContent>(
    item: &T,
    optional_public_key: Option<String>,
) -> Result<Vec<u8>> {
    let public_key_str = match optional_public_key {
        Some(key) => key,
        None => item.get_public_key()?,
    };

    let public_key = decode_public_key(&public_key_str)
        .map_err(|_| PrismError::General(GeneralError::InvalidPublicKey))?;

    let content = item.get_plaintext()?;
    let signature = item.get_signature()?;

    match public_key.verify(&signature, content.as_slice()) {
        Ok(_) => Ok(content),
        Err(e) => Err(GeneralError::InvalidSignature(e).into()),
    }
}
