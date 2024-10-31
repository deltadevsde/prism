use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use ed25519_consensus::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerificationKey as Ed25519VerifyingKey,
};
use secp256k1::{
    ecdsa::Signature as Secp256k1Signature, Message as Secp256k1Message,
    PublicKey as Secp256k1VerifyingKey, SecretKey as Secp256k1SigningKey, SECP256K1,
};
use serde::{Deserialize, Serialize};
use std::{self};

use crate::digest::Digest;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
/// Represents a public key supported by the system.
pub enum VerifyingKey {
    /// Bitcoin, Ethereum
    Secp256k1(Vec<u8>),
    /// Cosmos, OpenSSH, GnuPG
    Ed25519(Vec<u8>),
}

impl VerifyingKey {
    /// Returns the byte representation of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            VerifyingKey::Ed25519(bytes) => bytes,
            VerifyingKey::Secp256k1(bytes) => bytes,
        }
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            return Err(anyhow!("Invalid signature length"));
        }
        match self {
            VerifyingKey::Ed25519(bytes) => {
                let vk = Ed25519VerifyingKey::try_from(bytes.as_slice()).map_err(|e| anyhow!(e))?;
                let signature = Ed25519Signature::try_from(signature).map_err(|e| anyhow!(e))?;
                vk.verify(&signature, message).map_err(|e| anyhow!(e))
            }
            VerifyingKey::Secp256k1(bytes) => {
                let hashed_message = Digest::hash(message).to_bytes();
                let vk = Secp256k1VerifyingKey::from_slice(bytes.as_slice())?;
                let message = Secp256k1Message::from_digest(hashed_message);
                let signature = Secp256k1Signature::from_compact(signature)?;

                vk.verify(SECP256K1, &message, &signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {}", e))
            }
        }
    }
}

impl From<Ed25519SigningKey> for VerifyingKey {
    fn from(sk: Ed25519SigningKey) -> Self {
        VerifyingKey::Ed25519(sk.verification_key().to_bytes().to_vec())
    }
}

impl From<Ed25519VerifyingKey> for VerifyingKey {
    fn from(vk: Ed25519VerifyingKey) -> Self {
        VerifyingKey::Ed25519(vk.to_bytes().to_vec())
    }
}

impl From<Secp256k1SigningKey> for VerifyingKey {
    fn from(sk: Secp256k1SigningKey) -> Self {
        sk.public_key(SECP256K1).into()
    }
}

impl From<Secp256k1VerifyingKey> for VerifyingKey {
    fn from(vk: Secp256k1VerifyingKey) -> Self {
        VerifyingKey::Secp256k1(vk.serialize().to_vec())
    }
}

impl TryFrom<String> for VerifyingKey {
    type Error = anyhow::Error;

    /// Attempts to create a `VerifyingKey` from a base64-encoded string.
    ///
    /// # Arguments
    ///
    /// * `s` - The base64-encoded string representation of the public key.
    ///
    /// Depending on the length of the input string, the function will attempt to
    /// decode it and create a `VerifyingKey` instance. According to the specifications,
    /// the input string should be either [32 bytes (Ed25519)](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5) or [33/65 bytes (Secp256k1)](https://www.secg.org/sec1-v2.pdf).
    /// The secp256k1 key can be either compressed (33 bytes) or uncompressed (65 bytes).
    ///
    /// # Returns
    ///
    /// * `Ok(VerifyingKey)` if the conversion was successful.
    /// * `Err` if the input is invalid or the conversion failed.
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        let bytes =
            engine.decode(s).map_err(|e| anyhow!("Failed to decode base64 string: {}", e))?;

        match bytes.len() {
            32 => Ok(VerifyingKey::Ed25519(bytes)),
            33 | 65 => Ok(VerifyingKey::Secp256k1(bytes)),
            _ => Err(anyhow!("Invalid public key length")),
        }
    }
}

#[derive(Clone)]
pub enum SigningKey {
    Ed25519(Box<Ed25519SigningKey>),
    Secp256k1(Secp256k1SigningKey),
}

impl SigningKey {
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(sk) => sk.sign(message).to_bytes().to_vec(),
            SigningKey::Secp256k1(sk) => {
                let hashed_message = Digest::hash(message).to_bytes();
                let message = Secp256k1Message::from_digest(hashed_message);
                let signature = SECP256K1.sign_ecdsa(&message, sk);
                signature.serialize_compact().to_vec()
            }
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            SigningKey::Ed25519(sk) => sk.verification_key().into(),
            SigningKey::Secp256k1(sk) => sk.public_key(SECP256K1).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_verifying_key_from_string_ed25519() {
        let ed25519_vk =
            SigningKey::Ed25519(Box::new(Ed25519SigningKey::new(OsRng))).verifying_key();
        let encoded = engine.encode(ed25519_vk.as_bytes());

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_ok());

        if let Ok(VerifyingKey::Ed25519(key_bytes)) = result {
            assert_eq!(key_bytes.len(), 32);
            assert_eq!(key_bytes, ed25519_vk.as_bytes());
        } else {
            panic!("Expected Ed25519 key");
        }
    }

    #[test]
    fn test_verifying_key_from_string_secp256k1_compressed() {
        let secp256k1_vk =
            SigningKey::Secp256k1(Secp256k1SigningKey::new(&mut OsRng)).verifying_key();
        let secp256k1_bytes = secp256k1_vk.as_bytes();
        let encoded = engine.encode(secp256k1_bytes);

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_ok());

        if let Ok(VerifyingKey::Secp256k1(key_bytes)) = result {
            dbg!(key_bytes.len());
            assert_eq!(key_bytes, secp256k1_bytes);
        } else {
            panic!("Expected Secp256k1 key");
        }
    }

    #[test]
    fn test_verifying_key_from_string_secp256k1_uncompressed() {
        let secp256k1_bytes = [0; 65];
        let encoded = engine.encode(secp256k1_bytes);

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_ok());

        if let Ok(VerifyingKey::Secp256k1(key_bytes)) = result {
            assert_eq!(key_bytes.len(), 65);
            assert_eq!(key_bytes, secp256k1_bytes);
        } else {
            panic!("Expected Secp256k1 key");
        }
    }

    #[test]
    fn test_verifying_key_from_string_invalid_length() {
        let invalid_bytes: [u8; 31] = [1; 31];
        let encoded = engine.encode(invalid_bytes);

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_err());
    }
}
