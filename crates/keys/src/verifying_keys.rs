use anyhow::{anyhow, bail, Result};
use ed25519_consensus::{SigningKey as Ed25519SigningKey, VerificationKey as Ed25519VerifyingKey};
use p256::{
    ecdsa::{
        signature::DigestVerifier, SigningKey as Secp256r1SigningKey,
        VerifyingKey as Secp256r1VerifyingKey,
    },
    pkcs8::{DecodePublicKey, EncodePublicKey},
};

use k256::ecdsa::{SigningKey as Secp256k1SigningKey, VerifyingKey as Secp256k1VerifyingKey};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::{
    self,
    borrow::Cow,
    hash::{Hash, Hasher},
};
use utoipa::{
    openapi::{RefOr, Schema},
    PartialSchema, ToSchema,
};

use crate::{payload::CryptoPayload, CryptoAlgorithm, Signature, SigningKey};
use prism_serde::base64::{FromBase64, ToBase64};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(try_from = "CryptoPayload", into = "CryptoPayload")]
/// Represents a public key.
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
            VerifyingKey::Secp256k1(vk) => vk.to_sec1_bytes().to_vec(),
            VerifyingKey::Secp256r1(vk) => vk.to_sec1_bytes().to_vec(),
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let der = match self {
            VerifyingKey::Ed25519(_) => bail!("Ed25519 vk to DER format is not implemented"),
            VerifyingKey::Secp256k1(vk) => vk.to_public_key_der()?.into_vec(),
            VerifyingKey::Secp256r1(vk) => vk.to_public_key_der()?.into_vec(),
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
        }
    }

    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            VerifyingKey::Ed25519(_) => CryptoAlgorithm::Ed25519,
            VerifyingKey::Secp256k1(_) => CryptoAlgorithm::Secp256k1,
            VerifyingKey::Secp256r1(_) => CryptoAlgorithm::Secp256r1,
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
        VerifyingKey::Secp256k1(sk.verifying_key().to_owned())
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
