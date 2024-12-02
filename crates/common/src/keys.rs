use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use ed25519_consensus::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerificationKey as Ed25519VerifyingKey,
};
use p256::ecdsa::{
    signature::{DigestSigner, DigestVerifier},
    Signature as Secp256r1Signature, SigningKey as Secp256r1SigningKey,
    VerifyingKey as Secp256r1VerifyingKey,
};
use rand::rngs::OsRng;
use secp256k1::{
    ecdsa::Signature as Secp256k1Signature, Message as Secp256k1Message,
    PublicKey as Secp256k1VerifyingKey, SecretKey as Secp256k1SigningKey, SECP256K1,
};

use crate::serde::CryptoPayload;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::{
    self,
    hash::{Hash, Hasher},
};

use crate::digest::Digest;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(try_from = "CryptoPayload", into = "CryptoPayload")]
pub enum Signature {
    Secp256k1(Secp256k1Signature),
    Ed25519(Ed25519Signature),
    Secp256r1(Secp256r1Signature),
    #[default]
    Placeholder,
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(sig) => sig.to_bytes().to_vec(),
            Signature::Secp256k1(sig) => sig.serialize_der().to_vec(),
            Signature::Secp256r1(sig) => sig.to_der().as_bytes().to_vec(),
            Signature::Placeholder => vec![],
        }
    }

    pub fn from_algorithm_and_bytes(algorithm: &str, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            "ed25519" => {
                Ed25519Signature::try_from(bytes).map(Signature::Ed25519).map_err(|e| e.into())
            }
            "secp256k1" => {
                Secp256k1Signature::from_der(bytes).map(Signature::Secp256k1).map_err(|e| e.into())
            }
            "secp256r1" => {
                Secp256r1Signature::from_der(bytes).map(Signature::Secp256r1).map_err(|e| e.into())
            }
            _ => bail!("Unexpected algorithm for Signature"),
        }
    }

    pub fn algorithm(&self) -> &'static str {
        match self {
            Signature::Ed25519(_) => "ed25519",
            Signature::Secp256k1(_) => "secp256k1",
            Signature::Secp256r1(_) => "secp256r1",
            Signature::Placeholder => "placeholder",
        }
    }
}

impl TryFrom<CryptoPayload> for Signature {
    type Error = anyhow::Error;

    fn try_from(value: CryptoPayload) -> std::result::Result<Self, Self::Error> {
        Signature::from_algorithm_and_bytes(&value.algorithm, &value.bytes)
    }
}

impl From<Signature> for CryptoPayload {
    fn from(signature: Signature) -> Self {
        CryptoPayload {
            algorithm: signature.algorithm().to_string(),
            bytes: signature.to_bytes(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(try_from = "CryptoPayload", into = "CryptoPayload")]
/// Represents a public key supported by the system.
pub enum VerifyingKey {
    /// Bitcoin, Ethereum
    Secp256k1(Secp256k1VerifyingKey),
    /// Cosmos, OpenSSH, GnuPG
    Ed25519(Ed25519VerifyingKey),
    // TLS, X.509 PKI, Passkeys
    Secp256r1(Secp256r1VerifyingKey),
}

impl Hash for VerifyingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            VerifyingKey::Ed25519(_) => {
                state.write_u8(0);
                self.to_bytes().hash(state);
            }
            VerifyingKey::Secp256k1(_) => {
                state.write_u8(1);
                self.to_bytes().hash(state);
            }
            VerifyingKey::Secp256r1(_) => {
                state.write_u8(2);
                self.to_bytes().hash(state);
            }
        }
    }
}

impl VerifyingKey {
    /// Returns the byte representation of the public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VerifyingKey::Ed25519(vk) => vk.to_bytes().to_vec(),
            VerifyingKey::Secp256k1(vk) => vk.serialize().to_vec(),
            VerifyingKey::Secp256r1(vk) => vk.to_sec1_bytes().to_vec(),
        }
    }

    pub fn from_algorithm_and_bytes(algorithm: &str, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            "ed25519" => Ed25519VerifyingKey::try_from(bytes)
                .map(VerifyingKey::Ed25519)
                .map_err(|e| e.into()),
            "secp256k1" => Secp256k1VerifyingKey::from_slice(bytes)
                .map(VerifyingKey::Secp256k1)
                .map_err(|e| e.into()),
            "secp256r1" => Secp256r1VerifyingKey::from_sec1_bytes(bytes)
                .map(VerifyingKey::Secp256r1)
                .map_err(|e| e.into()),
            _ => bail!("Unexpected algorithm for VerifyingKey"),
        }
    }

    pub fn algorithm(&self) -> &'static str {
        match self {
            VerifyingKey::Ed25519(_) => "ed25519",
            VerifyingKey::Secp256k1(_) => "secp256k1",
            VerifyingKey::Secp256r1(_) => "secp256r1",
        }
    }

    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> Result<()> {
        match self {
            VerifyingKey::Ed25519(vk) => {
                let Signature::Ed25519(signature) = signature else {
                    bail!("Invalid signature type");
                };

                vk.verify(signature, message)
                    .map_err(|e| anyhow!("Failed to verify signature: {}", e))
            }
            VerifyingKey::Secp256k1(vk) => {
                let Signature::Secp256k1(signature) = signature else {
                    bail!("Invalid signature type");
                };
                let hashed_message = Digest::hash(message).to_bytes();
                let message = Secp256k1Message::from_digest(hashed_message);
                vk.verify(SECP256K1, &message, signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {}", e))
            }
            VerifyingKey::Secp256r1(vk) => {
                let Signature::Secp256r1(signature) = signature else {
                    bail!("Invalid signature type");
                };
                let mut digest = sha2::Sha256::new();
                digest.update(message);

                let der_sig = signature.to_der();
                vk.verify_digest(digest, &der_sig)
                    .map_err(|e| anyhow!("Failed to verify signature: {}", e))
            }
        }
    }
}

impl TryFrom<CryptoPayload> for VerifyingKey {
    type Error = anyhow::Error;

    fn try_from(value: CryptoPayload) -> std::result::Result<Self, Self::Error> {
        VerifyingKey::from_algorithm_and_bytes(&value.algorithm, &value.bytes)
    }
}

impl From<VerifyingKey> for CryptoPayload {
    fn from(signature: VerifyingKey) -> Self {
        CryptoPayload {
            algorithm: signature.algorithm().to_string(),
            bytes: signature.to_bytes(),
        }
    }
}

impl From<Ed25519VerifyingKey> for VerifyingKey {
    fn from(vk: Ed25519VerifyingKey) -> Self {
        VerifyingKey::Ed25519(vk)
    }
}

impl From<Secp256k1VerifyingKey> for VerifyingKey {
    fn from(vk: Secp256k1VerifyingKey) -> Self {
        VerifyingKey::Secp256k1(vk)
    }
}

impl From<Secp256r1VerifyingKey> for VerifyingKey {
    fn from(vk: Secp256r1VerifyingKey) -> Self {
        VerifyingKey::Secp256r1(vk)
    }
}

impl From<Ed25519SigningKey> for VerifyingKey {
    fn from(sk: Ed25519SigningKey) -> Self {
        VerifyingKey::Ed25519(sk.verification_key())
    }
}

impl From<Secp256k1SigningKey> for VerifyingKey {
    fn from(sk: Secp256k1SigningKey) -> Self {
        sk.public_key(SECP256K1).into()
    }
}

impl From<Secp256r1SigningKey> for VerifyingKey {
    fn from(sk: Secp256r1SigningKey) -> Self {
        VerifyingKey::Secp256r1(sk.verifying_key().to_owned())
    }
}

impl From<SigningKey> for VerifyingKey {
    fn from(sk: SigningKey) -> Self {
        match sk {
            SigningKey::Ed25519(sk) => (*sk).into(),
            SigningKey::Secp256k1(sk) => sk.into(),
            SigningKey::Secp256r1(sk) => sk.into(),
        }
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
            32 => {
                let vk = Ed25519VerifyingKey::try_from(bytes.as_slice())
                    .map_err(|e| anyhow!("Invalid Ed25519 key: {}", e))?;
                Ok(VerifyingKey::Ed25519(vk))
            }
            33 | 65 => {
                let vk = Secp256k1VerifyingKey::from_slice(bytes.as_slice())
                    .map_err(|e| anyhow!("Invalid Secp256k1 key: {}", e))?;
                Ok(VerifyingKey::Secp256k1(vk))
            }
            _ => Err(anyhow!("Invalid public key length")),
        }
    }
}

impl std::fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let encoded = engine.encode(self.to_bytes());
        write!(f, "{}", encoded)
    }
}

#[derive(Clone, Debug)]
pub enum SigningKey {
    Ed25519(Box<Ed25519SigningKey>),
    Secp256k1(Secp256k1SigningKey),
    Secp256r1(Secp256r1SigningKey),
}

impl SigningKey {
    pub fn new_ed25519() -> Self {
        SigningKey::Ed25519(Box::new(Ed25519SigningKey::new(OsRng)))
    }

    pub fn new_secp256k1() -> Self {
        SigningKey::Secp256k1(Secp256k1SigningKey::new(&mut OsRng))
    }

    pub fn new_secp256r1() -> Self {
        SigningKey::Secp256r1(Secp256r1SigningKey::random(&mut OsRng))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.clone().into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(sk) => sk.to_bytes().to_vec(),
            SigningKey::Secp256k1(sk) => sk.secret_bytes().to_vec(),
            SigningKey::Secp256r1(sk) => sk.to_bytes().to_vec(),
        }
    }

    pub fn from_algorithm_and_bytes(algorithm: &str, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            "ed25519" => Ed25519SigningKey::try_from(bytes)
                .map(|sk| SigningKey::Ed25519(Box::new(sk)))
                .map_err(|e| e.into()),
            "secp256k1" => Secp256k1SigningKey::from_slice(bytes)
                .map(SigningKey::Secp256k1)
                .map_err(|e| e.into()),
            "secp256r1" => Secp256r1SigningKey::from_slice(bytes)
                .map(SigningKey::Secp256r1)
                .map_err(|e| e.into()),
            _ => bail!("Unexpected algorithm for SigningKey"),
        }
    }

    pub fn algorithm(&self) -> &'static str {
        match self {
            SigningKey::Ed25519(_) => "ed25519",
            SigningKey::Secp256k1(_) => "secp256k1",
            SigningKey::Secp256r1(_) => "secp256r1",
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            SigningKey::Ed25519(sk) => Signature::Ed25519(sk.sign(message)),
            SigningKey::Secp256k1(sk) => {
                let hashed_message = Digest::hash(message).to_bytes();
                let message = Secp256k1Message::from_digest(hashed_message);
                let signature = SECP256K1.sign_ecdsa(&message, sk);
                Signature::Secp256k1(signature)
            }
            SigningKey::Secp256r1(sk) => {
                let mut digest = sha2::Sha256::new();
                digest.update(message);
                let sig: Secp256r1Signature = sk.sign_digest(digest);
                Signature::Secp256r1(sig)
            }
        }
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SigningKey::Ed25519(a), SigningKey::Ed25519(b)) => a.as_bytes() == b.as_bytes(),
            (SigningKey::Secp256k1(a), SigningKey::Secp256k1(b)) => a == b,
            (SigningKey::Secp256r1(a), SigningKey::Secp256r1(b)) => a == b,
            _ => false,
        }
    }
}

impl TryFrom<CryptoPayload> for SigningKey {
    type Error = anyhow::Error;

    fn try_from(value: CryptoPayload) -> std::result::Result<Self, Self::Error> {
        SigningKey::from_algorithm_and_bytes(&value.algorithm, &value.bytes)
    }
}

impl From<SigningKey> for CryptoPayload {
    fn from(signing_key: SigningKey) -> Self {
        CryptoPayload {
            algorithm: signing_key.algorithm().to_string(),
            bytes: signing_key.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_reparsed_verifying_keys_are_equal_to_original() {
        let verifying_key_ed25519 = SigningKey::new_ed25519().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_bytes(
            verifying_key_ed25519.algorithm(),
            &verifying_key_ed25519.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_ed25519);

        let verifying_key_secp256k1 = SigningKey::new_secp256k1().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_bytes(
            verifying_key_secp256k1.algorithm(),
            &verifying_key_secp256k1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_secp256k1);

        let verifying_key_secp256r1 = SigningKey::new_secp256r1().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_bytes(
            verifying_key_secp256r1.algorithm(),
            &verifying_key_secp256r1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_secp256r1);
    }

    #[test]
    fn test_reparsed_signing_keys_are_equal_to_original() {
        let signing_key_ed25519 = SigningKey::new_ed25519();
        let re_parsed_signing_key = SigningKey::from_algorithm_and_bytes(
            signing_key_ed25519.algorithm(),
            &signing_key_ed25519.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signing_key, signing_key_ed25519);

        let signing_key_secp256k1 = SigningKey::new_secp256k1();
        let re_parsed_signing_key = SigningKey::from_algorithm_and_bytes(
            signing_key_secp256k1.algorithm(),
            &signing_key_secp256k1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signing_key, signing_key_secp256k1);

        let signing_key_secp256r1 = SigningKey::new_secp256r1();
        let re_parsed_signing_key = SigningKey::from_algorithm_and_bytes(
            signing_key_secp256r1.algorithm(),
            &signing_key_secp256r1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signing_key, signing_key_secp256r1);
    }

    #[test]
    fn test_reparsed_signatures_are_equal_to_original() {
        let message = b"test message";

        let signature_ed25519 = SigningKey::new_ed25519().sign(message);
        let re_parsed_signature = Signature::from_algorithm_and_bytes(
            signature_ed25519.algorithm(),
            &signature_ed25519.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_ed25519);

        let signature_secp256k1 = SigningKey::new_secp256k1().sign(message);
        let re_parsed_signature = Signature::from_algorithm_and_bytes(
            signature_secp256k1.algorithm(),
            &signature_secp256k1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_secp256k1);

        let signature_secp256r1 = SigningKey::new_secp256r1().sign(message);
        let re_parsed_signature = Signature::from_algorithm_and_bytes(
            signature_secp256r1.algorithm(),
            &signature_secp256r1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_secp256r1);
    }

    #[test]
    fn test_verifying_key_from_string_ed25519() {
        let original_key: VerifyingKey =
            SigningKey::Ed25519(Box::new(Ed25519SigningKey::new(OsRng))).into();
        let encoded = engine.encode(original_key.to_bytes());

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_ok());

        let decoded_key = result.unwrap();
        assert_eq!(decoded_key.to_bytes(), original_key.to_bytes());
    }

    #[test]
    fn test_verifying_key_from_string_secp256k1() {
        let original_key: VerifyingKey =
            SigningKey::Secp256k1(Secp256k1SigningKey::new(&mut OsRng)).into();
        let encoded = engine.encode(original_key.to_bytes());

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_ok());

        let decoded_key = result.unwrap();
        assert_eq!(decoded_key.to_bytes(), original_key.to_bytes());
    }

    #[test]
    fn test_verifying_key_from_string_invalid_length() {
        let invalid_bytes: [u8; 31] = [1; 31];
        let encoded = engine.encode(invalid_bytes);

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_err());
    }
}
