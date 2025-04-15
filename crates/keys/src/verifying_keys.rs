use alloy_primitives::eip191_hash_message;
use anyhow::{Result, anyhow, bail};
use ed25519_consensus::VerificationKey as Ed25519VerifyingKey;
use p256::{
    ecdsa::{
        VerifyingKey as Secp256r1VerifyingKey,
        signature::{DigestVerifier, hazmat::PrehashVerifier},
    },
    pkcs8::{DecodePublicKey, EncodePublicKey},
};

use k256::ecdsa::VerifyingKey as Secp256k1VerifyingKey;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::{
    self,
    borrow::Cow,
    hash::{Hash, Hasher},
};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{RefOr, Schema},
};

use crate::{
    CryptoAlgorithm, Signature, SigningKey, cosmos::cosmos_adr36_hash_message,
    payload::CryptoPayload,
};
use prism_serde::base64::{FromBase64, ToBase64};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(try_from = "CryptoPayload", into = "CryptoPayload")]
/// Represents a public key.
pub enum VerifyingKey {
    /// Bitcoin, Ethereum
    Secp256k1(Secp256k1VerifyingKey),
    /// Cosmos, OpenSSH, GnuPG
    Ed25519(Ed25519VerifyingKey),
    /// TLS, X.509 PKI, Passkeys
    Secp256r1(Secp256r1VerifyingKey),
    /// Verifies signatures according to EIP-191
    Eip191(Secp256k1VerifyingKey),
    /// Verifies signatures according to Cosmos ADR-36
    CosmosAdr36(Secp256k1VerifyingKey),
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
            VerifyingKey::Eip191(_) => {
                state.write_u8(3);
                self.to_bytes().hash(state);
            }
            VerifyingKey::CosmosAdr36(_) => {
                state.write_u8(4);
                self.to_bytes().hash(state);
            }
        }
    }
}

impl VerifyingKey {
    /// Returns the byte representation of the public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VerifyingKey::Ed25519(vk) => vk.as_bytes().to_vec(),
            VerifyingKey::Secp256k1(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
            VerifyingKey::Secp256r1(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
            VerifyingKey::Eip191(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
            VerifyingKey::CosmosAdr36(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let der = match self {
            VerifyingKey::Ed25519(_) => bail!("Ed25519 vk to DER format is not implemented"),
            VerifyingKey::Secp256k1(vk) => vk.to_public_key_der()?.into_vec(),
            VerifyingKey::Secp256r1(vk) => vk.to_public_key_der()?.into_vec(),
            VerifyingKey::Eip191(_) => bail!("EIP-191 vk to DER format is not implemented"),
            VerifyingKey::CosmosAdr36(_) => {
                bail!("Cosmos ADR-36 vk to DER format is not implemented")
            }
        };
        Ok(der)
    }

    pub fn from_algorithm_and_bytes(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => Ed25519VerifyingKey::try_from(bytes)
                .map(VerifyingKey::Ed25519)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Secp256k1 => Secp256k1VerifyingKey::from_sec1_bytes(bytes)
                .map(VerifyingKey::Secp256k1)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Secp256r1 => Secp256r1VerifyingKey::from_sec1_bytes(bytes)
                .map(VerifyingKey::Secp256r1)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Eip191 => Secp256k1VerifyingKey::from_sec1_bytes(bytes)
                .map(VerifyingKey::Eip191)
                .map_err(|e| e.into()),
            CryptoAlgorithm::CosmosAdr36 => Secp256k1VerifyingKey::from_sec1_bytes(bytes)
                .map(VerifyingKey::CosmosAdr36)
                .map_err(|e| e.into()),
        }
    }

    pub fn from_algorithm_and_der(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => bail!("Ed25519 vk from DER format is not implemented"),
            CryptoAlgorithm::Secp256k1 => Secp256k1VerifyingKey::from_public_key_der(bytes)
                .map(VerifyingKey::Secp256k1)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Secp256r1 => Secp256r1VerifyingKey::from_public_key_der(bytes)
                .map(VerifyingKey::Secp256r1)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Eip191 => bail!("Eth vk from DER format is not implemented"),
            CryptoAlgorithm::CosmosAdr36 => {
                bail!("Cosmos ADR-36 vk from DER format is not implemented")
            }
        }
    }

    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            VerifyingKey::Ed25519(_) => CryptoAlgorithm::Ed25519,
            VerifyingKey::Secp256k1(_) => CryptoAlgorithm::Secp256k1,
            VerifyingKey::Secp256r1(_) => CryptoAlgorithm::Secp256r1,
            VerifyingKey::Eip191(_) => CryptoAlgorithm::Eip191,
            VerifyingKey::CosmosAdr36(_) => CryptoAlgorithm::CosmosAdr36,
        }
    }

    pub fn verify_signature(&self, message: impl AsRef<[u8]>, signature: &Signature) -> Result<()> {
        match self {
            VerifyingKey::Ed25519(vk) => {
                let Signature::Ed25519(signature) = signature else {
                    bail!("Invalid signature type");
                };

                vk.verify(signature, message.as_ref())
                    .map_err(|e| anyhow!("Failed to verify ed25519 signature: {}", e))
            }
            VerifyingKey::Secp256k1(vk) => {
                let Signature::Secp256k1(signature) = signature else {
                    bail!("Invalid signature type");
                };
                let mut digest = sha2::Sha256::new();
                digest.update(message);

                vk.verify_digest(digest, signature)
                    .map_err(|e| anyhow!("Failed to verify secp256k1 signature: {}", e))
            }
            VerifyingKey::Secp256r1(vk) => {
                let Signature::Secp256r1(signature) = signature else {
                    bail!("Invalid signature type");
                };
                let mut digest = sha2::Sha256::new();
                digest.update(message);

                vk.verify_digest(digest, signature)
                    .map_err(|e| anyhow!("Failed to verify secp256r1 signature: {}", e))
            }
            VerifyingKey::Eip191(vk) => {
                let Signature::Secp256k1(signature) = signature else {
                    bail!("Verifying key for EIP-191 can only verify secp256k1 signatures");
                };
                let prehash = eip191_hash_message(message);
                vk.verify_prehash(prehash.as_slice(), signature)
                    .map_err(|e| anyhow!("Failed to verify EIP-191 signature: {}", e))
            }
            VerifyingKey::CosmosAdr36(vk) => {
                let Signature::Secp256k1(signature) = signature else {
                    bail!("Verifying key for cosmos ADR-36 can only verify secp256k1 signatures");
                };
                let prehash = cosmos_adr36_hash_message(message, vk)?;
                vk.verify_prehash(&prehash, signature)
                    .map_err(|e| anyhow!("Failed to verify cosmos ADR-36 signature: {}", e))
            }
        }
    }
}

impl TryFrom<CryptoPayload> for VerifyingKey {
    type Error = anyhow::Error;

    fn try_from(value: CryptoPayload) -> std::result::Result<Self, Self::Error> {
        VerifyingKey::from_algorithm_and_bytes(value.algorithm, &value.bytes)
    }
}

impl From<VerifyingKey> for CryptoPayload {
    fn from(verifying_key: VerifyingKey) -> Self {
        CryptoPayload {
            algorithm: verifying_key.algorithm(),
            bytes: verifying_key.to_bytes(),
        }
    }
}

impl From<SigningKey> for VerifyingKey {
    fn from(sk: SigningKey) -> Self {
        match sk {
            SigningKey::Ed25519(sk) => VerifyingKey::Ed25519(sk.verification_key()),
            SigningKey::Secp256k1(sk) => VerifyingKey::Secp256k1(sk.verifying_key().to_owned()),
            SigningKey::Secp256r1(sk) => VerifyingKey::Secp256r1(sk.verifying_key().to_owned()),
            SigningKey::Eip191(sk) => VerifyingKey::Eip191(sk.verifying_key().to_owned()),
            SigningKey::CosmosAdr36(sk) => VerifyingKey::CosmosAdr36(sk.verifying_key().to_owned()),
        }
    }
}

impl FromBase64 for VerifyingKey {
    type Error = anyhow::Error;

    fn from_base64<T: AsRef<[u8]>>(base64: T) -> Result<Self, Self::Error> {
        let bytes = Vec::<u8>::from_base64(base64)?;

        match bytes.len() {
            32 => {
                let vk = Ed25519VerifyingKey::try_from(bytes.as_slice())
                    .map_err(|e| anyhow!("Invalid Ed25519 key: {}", e))?;
                Ok(VerifyingKey::Ed25519(vk))
            }
            _ => Err(anyhow!("Only Ed25519 keys can be initialized from base64")),
        }
    }
}

impl TryFrom<String> for VerifyingKey {
    type Error = anyhow::Error;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        Self::from_base64(s)
    }
}

impl std::fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let encoded = self.to_bytes().to_base64();
        write!(f, "{}", encoded)
    }
}

/// Necessary to represent `VerifyingKey` as `CryptoPayload` in the OpenAPI spec.
/// Workaround, because `schema(as = CryptoPayload)` currently requires all wrapped
/// native key types in the enum variants to implement `ToSchema` as well.
impl ToSchema for VerifyingKey {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("CryptoPayload")
    }

    fn schemas(_schemas: &mut Vec<(String, RefOr<Schema>)>) {
        CryptoPayload::schemas(_schemas);
    }
}

impl PartialSchema for VerifyingKey {
    fn schema() -> RefOr<Schema> {
        CryptoPayload::schema()
    }
}
