use anyhow::{anyhow, bail, Result};
use ed25519_consensus::{SigningKey as Ed25519SigningKey, VerificationKey as Ed25519VerifyingKey};
use p256::{
    ecdsa::{
        signature::DigestVerifier, SigningKey as Secp256r1SigningKey,
        VerifyingKey as Secp256r1VerifyingKey,
    },
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use secp256k1::{
    Message as Secp256k1Message, PublicKey as Secp256k1VerifyingKey,
    SecretKey as Secp256k1SigningKey, SECP256K1,
};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::{
    self,
    hash::{Hash, Hasher},
};

use crate::{payload::CryptoPayload, CryptoAlgorithm, Signature, SigningKey};
use prism_serde::base64::{FromBase64, ToBase64};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(try_from = "CryptoPayload", into = "CryptoPayload")]
/// Represents a public key.
pub enum PublicKey {
    /// Bitcoin, Ethereum
    Secp256k1(Secp256k1VerifyingKey),
    /// Cosmos, OpenSSH, GnuPG
    Ed25519(Ed25519VerifyingKey),
    // TLS, X.509 PKI, Passkeys
    Secp256r1(Secp256r1VerifyingKey),
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PublicKey::Ed25519(_) => {
                state.write_u8(0);
                self.to_bytes().hash(state);
            }
            PublicKey::Secp256k1(_) => {
                state.write_u8(1);
                self.to_bytes().hash(state);
            }
            PublicKey::Secp256r1(_) => {
                state.write_u8(2);
                self.to_bytes().hash(state);
            }
        }
    }
}

impl PublicKey {
    /// Returns the byte representation of the public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(vk) => vk.to_bytes().to_vec(),
            PublicKey::Secp256k1(vk) => vk.serialize().to_vec(),
            PublicKey::Secp256r1(vk) => vk.to_sec1_bytes().to_vec(),
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let der = match self {
            PublicKey::Ed25519(_) => bail!("Ed25519 vk to DER format is not implemented"),
            PublicKey::Secp256k1(_) => bail!("Secp256k1 vk to DER format is not implemented"),
            PublicKey::Secp256r1(vk) => vk.to_public_key_der()?.into_vec(),
        };
        Ok(der)
    }

    pub fn from_algorithm_and_bytes(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => Ed25519VerifyingKey::try_from(bytes)
                .map(PublicKey::Ed25519)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Secp256k1 => Secp256k1VerifyingKey::from_slice(bytes)
                .map(PublicKey::Secp256k1)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Secp256r1 => Secp256r1VerifyingKey::from_sec1_bytes(bytes)
                .map(PublicKey::Secp256r1)
                .map_err(|e| e.into()),
        }
    }

    pub fn from_algorithm_and_der(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => bail!("Ed25519 vk from DER format is not implemented"),
            CryptoAlgorithm::Secp256k1 => bail!("Secp256k1 vk from DER format is not implemented"),
            CryptoAlgorithm::Secp256r1 => Secp256r1VerifyingKey::from_public_key_der(bytes)
                .map(PublicKey::Secp256r1)
                .map_err(|e| e.into()),
        }
    }

    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            PublicKey::Ed25519(_) => CryptoAlgorithm::Ed25519,
            PublicKey::Secp256k1(_) => CryptoAlgorithm::Secp256k1,
            PublicKey::Secp256r1(_) => CryptoAlgorithm::Secp256r1,
        }
    }

    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> Result<()> {
        match self {
            PublicKey::Ed25519(vk) => {
                let Signature::Ed25519(signature) = signature else {
                    bail!("Invalid signature type");
                };

                vk.verify(signature, message)
                    .map_err(|e| anyhow!("Failed to verify signature: {}", e))
            }
            PublicKey::Secp256k1(vk) => {
                let Signature::Secp256k1(signature) = signature else {
                    bail!("Invalid signature type");
                };

                let digest = sha2::Sha256::digest(message);
                let message = Secp256k1Message::from_digest(digest.into());
                vk.verify(SECP256K1, &message, signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {}", e))
            }
            PublicKey::Secp256r1(vk) => {
                let Signature::Secp256r1(signature) = signature else {
                    bail!("Invalid signature type");
                };
                let mut digest = sha2::Sha256::new();
                digest.update(message);

                vk.verify_digest(digest, signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {}", e))
            }
        }
    }
}

impl TryFrom<CryptoPayload> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: CryptoPayload) -> std::result::Result<Self, Self::Error> {
        PublicKey::from_algorithm_and_bytes(value.algorithm, &value.bytes)
    }
}

impl From<PublicKey> for CryptoPayload {
    fn from(verifying_key: PublicKey) -> Self {
        CryptoPayload {
            algorithm: verifying_key.algorithm(),
            bytes: verifying_key.to_bytes(),
        }
    }
}

impl From<Ed25519VerifyingKey> for PublicKey {
    fn from(vk: Ed25519VerifyingKey) -> Self {
        PublicKey::Ed25519(vk)
    }
}

impl From<Secp256k1VerifyingKey> for PublicKey {
    fn from(vk: Secp256k1VerifyingKey) -> Self {
        PublicKey::Secp256k1(vk)
    }
}

impl From<Secp256r1VerifyingKey> for PublicKey {
    fn from(vk: Secp256r1VerifyingKey) -> Self {
        PublicKey::Secp256r1(vk)
    }
}

impl From<Ed25519SigningKey> for PublicKey {
    fn from(sk: Ed25519SigningKey) -> Self {
        PublicKey::Ed25519(sk.verification_key())
    }
}

impl From<Secp256k1SigningKey> for PublicKey {
    fn from(sk: Secp256k1SigningKey) -> Self {
        PublicKey::Secp256k1(sk.public_key(SECP256K1))
    }
}

impl From<Secp256r1SigningKey> for PublicKey {
    fn from(sk: Secp256r1SigningKey) -> Self {
        PublicKey::Secp256r1(sk.verifying_key().to_owned())
    }
}

impl From<SigningKey> for PublicKey {
    fn from(sk: SigningKey) -> Self {
        match sk {
            SigningKey::Ed25519(sk) => (*sk).into(),
            SigningKey::Secp256k1(sk) => sk.into(),
            SigningKey::Secp256r1(sk) => sk.into(),
        }
    }
}

impl FromBase64 for PublicKey {
    type Error = anyhow::Error;

    /// Attempts to create a `VerifyingKey` from a base64-encoded string.
    ///
    /// # Arguments
    ///
    /// * `base64` - The base64-encoded string representation of the public key.
    ///
    /// Depending on the length of the input string, the function will attempt to
    /// decode it and create a `VerifyingKey` instance. According to the specifications,
    /// the input string should be either [32 bytes (Ed25519)](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5) or [33/65 bytes (Secp256k1 or Secp256r1)](https://www.secg.org/sec1-v2.pdf).
    /// The secp256k1 and secp256r1 keys can be either compressed (33 bytes) or uncompressed (65 bytes).
    ///
    /// # Returns
    ///
    /// * `Ok(VerifyingKey)` if the conversion was successful.
    /// * `Err` if the input is invalid or the conversion failed.
    fn from_base64<T: AsRef<[u8]>>(base64: T) -> Result<Self, Self::Error> {
        let bytes = Vec::<u8>::from_base64(base64)?;

        match bytes.len() {
            32 => {
                let vk = Ed25519VerifyingKey::try_from(bytes.as_slice())
                    .map_err(|e| anyhow!("Invalid Ed25519 key: {}", e))?;
                Ok(PublicKey::Ed25519(vk))
            }
            33 | 65 => {
                if let Ok(vk) = Secp256k1VerifyingKey::from_slice(bytes.as_slice()) {
                    Ok(PublicKey::Secp256k1(vk))
                } else if let Ok(vk) = Secp256r1VerifyingKey::from_sec1_bytes(bytes.as_slice()) {
                    Ok(PublicKey::Secp256r1(vk))
                } else {
                    Err(anyhow!("Invalid curve type"))
                }
            }
            _ => Err(anyhow!("Invalid public key length")),
        }
    }
}

impl TryFrom<String> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        Self::from_base64(s)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let encoded = self.to_bytes().to_base64();
        write!(f, "{}", encoded)
    }
}
