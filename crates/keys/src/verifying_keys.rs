use crate::{
    CryptoError, Result,
    errors::{ParseError, SignatureError, VerificationError},
};
use alloy_primitives::eip191_hash_message;
use ed25519::PublicKeyBytes as Ed25519PublicKeyBytes;
use ed25519_consensus::VerificationKey as Ed25519VerifyingKey;
use k256::ecdsa::VerifyingKey as Secp256k1VerifyingKey;
use p256::{
    ecdsa::{
        VerifyingKey as Secp256r1VerifyingKey,
        signature::{DigestVerifier, hazmat::PrehashVerifier},
    },
    pkcs8::EncodePublicKey,
};
use pkcs8::{
    Document, LineEnding, SubjectPublicKeyInfoRef,
    der::{Decode, pem::PemLabel},
};
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use sha2::Digest as _;
use std::{
    self,
    borrow::Cow,
    hash::{Hash, Hasher},
    path::Path,
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

    pub fn from_algorithm_and_bytes(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => {
                Ed25519VerifyingKey::try_from(bytes).map(VerifyingKey::Ed25519).map_err(|e| {
                    VerificationError::VerifyError("ed25519".to_string(), e.to_string()).into()
                })
            }
            CryptoAlgorithm::Secp256k1 => Secp256k1VerifyingKey::from_sec1_bytes(bytes)
                .map(VerifyingKey::Secp256k1)
                .map_err(|e| {
                    VerificationError::VerifyError("secp256k1".to_string(), e.to_string()).into()
                }),
            CryptoAlgorithm::Secp256r1 => Secp256r1VerifyingKey::from_sec1_bytes(bytes)
                .map(VerifyingKey::Secp256r1)
                .map_err(|e| {
                    VerificationError::VerifyError("secp256r1".to_string(), e.to_string()).into()
                }),
            CryptoAlgorithm::Eip191 => {
                Secp256k1VerifyingKey::from_sec1_bytes(bytes).map(VerifyingKey::Eip191).map_err(
                    |e| VerificationError::VerifyError("eip191".to_string(), e.to_string()).into(),
                )
            }
            CryptoAlgorithm::CosmosAdr36 => Secp256k1VerifyingKey::from_sec1_bytes(bytes)
                .map(VerifyingKey::CosmosAdr36)
                .map_err(|e| {
                    VerificationError::VerifyError("cosmos adr36".to_string(), e.to_string()).into()
                }),
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
                    return Err(SignatureError::InvalidSignError.into());
                };

                vk.verify(signature, message.as_ref()).map_err(|e| {
                    VerificationError::VerifyError("ed25519".to_string(), e.to_string()).into()
                })
            }
            VerifyingKey::Secp256k1(vk) => {
                let Signature::Secp256k1(signature) = signature else {
                    return Err(SignatureError::InvalidSignError.into());
                };
                let mut digest = sha2::Sha256::new();
                digest.update(message);

                vk.verify_digest(digest, signature).map_err(|e| {
                    VerificationError::VerifyError("secp256k1".to_string(), e.to_string()).into()
                })
            }
            VerifyingKey::Secp256r1(vk) => {
                let Signature::Secp256r1(signature) = signature else {
                    return Err(SignatureError::InvalidSignError.into());
                };
                let mut digest = sha2::Sha256::new();
                digest.update(message);

                vk.verify_digest(digest, signature).map_err(|e| {
                    VerificationError::VerifyError("secp256r1".to_string(), e.to_string()).into()
                })
            }
            VerifyingKey::Eip191(vk) => {
                let Signature::Secp256k1(signature) = signature else {
                    return Err(VerificationError::SignatureError("EIP-191".to_string()).into());
                };
                let prehash = eip191_hash_message(message);
                vk.verify_prehash(prehash.as_slice(), signature).map_err(|e| {
                    VerificationError::VerifyError("EIP-191".to_string(), e.to_string()).into()
                })
            }
            VerifyingKey::CosmosAdr36(vk) => {
                let Signature::Secp256k1(signature) = signature else {
                    return Err(
                        VerificationError::SignatureError("cosmos ADR-36".to_string()).into(),
                    );
                };
                let prehash = cosmos_adr36_hash_message(message, vk)
                    .map_err(|e| VerificationError::GeneralError(e.to_string()))?;
                vk.verify_prehash(&prehash, signature).map_err(|e| {
                    VerificationError::VerifyError("cosmos ADR-36".to_string(), e.to_string())
                        .into()
                })
            }
        }
    }

    fn to_spki_der_doc(&self) -> Result<Document> {
        match self {
            VerifyingKey::Ed25519(vk) => Ed25519PublicKeyBytes(vk.to_bytes()).to_public_key_der(),
            VerifyingKey::Secp256k1(vk) => vk.to_public_key_der(),
            VerifyingKey::Secp256r1(vk) => vk.to_public_key_der(),
            VerifyingKey::Eip191(_) => {
                return Err(CryptoError::VerificationError(
                    VerificationError::NotImplementedError("EIP-191".to_string(), "to".to_string()),
                ));
            }
            VerifyingKey::CosmosAdr36(_) => {
                return Err(CryptoError::VerificationError(
                    VerificationError::NotImplementedError(
                        "cosmos ADR-36".to_string(),
                        "to".to_string(),
                    ),
                ));
            }
        }
        .map_err(|_| ParseError::DerCreationError.into())
    }

    pub fn to_spki_der(&self) -> Result<Vec<u8>> {
        Ok(self.to_spki_der_doc()?.as_bytes().to_vec())
    }

    pub fn to_spki_pem_file(&self, filename: impl AsRef<Path>) -> Result<()> {
        self.to_spki_der_doc()?
            .write_pem_file(filename, SubjectPublicKeyInfoRef::PEM_LABEL, LineEnding::LF)
            .map_err(|_| VerificationError::VKCreationError("PKCS8 PEM file".to_string()).into())
    }

    fn from_spki(spki: SubjectPublicKeyInfoRef) -> Result<Self> {
        let algorithm = CryptoAlgorithm::try_from(spki.algorithm)
            .map_err(|e| ParseError::GeneralError(e.to_string()))?;

        match algorithm {
            CryptoAlgorithm::Ed25519 => {
                let ed25519_spki = Ed25519PublicKeyBytes::try_from(spki)
                    .map_err(|e| ParseError::GeneralError(e.to_string()))?;
                let ed25519_key = Ed25519VerifyingKey::try_from(ed25519_spki.as_ref() as &[u8])
                    .map_err(|e| {
                        VerificationError::IntoRefError("ed25519".to_string(), e.to_string())
                    })?;
                Ok(VerifyingKey::Ed25519(ed25519_key))
            }
            CryptoAlgorithm::Secp256k1 => {
                let secp256k1_key = Secp256k1VerifyingKey::try_from(spki).map_err(|e| {
                    VerificationError::IntoRefError("secp256k1".to_string(), e.to_string())
                })?;
                Ok(VerifyingKey::Secp256k1(secp256k1_key))
            }
            CryptoAlgorithm::Secp256r1 => {
                let secp256r1_key = Secp256r1VerifyingKey::try_from(spki).map_err(|e| {
                    VerificationError::IntoRefError("secp256r1".to_string(), e.to_string())
                })?;
                Ok(VerifyingKey::Secp256r1(secp256r1_key))
            }
            CryptoAlgorithm::Eip191 => Err(VerificationError::NotImplementedError(
                "Eth".to_string(),
                "from".to_string(),
            )
            .into()),
            CryptoAlgorithm::CosmosAdr36 => Err(VerificationError::NotImplementedError(
                "Cosmos ADR-36".to_string(),
                "from".to_string(),
            )
            .into()),
        }
    }

    pub fn from_spki_der(bytes: &[u8]) -> Result<Self> {
        let spki = SubjectPublicKeyInfoRef::from_der(bytes)
            .map_err(|e| ParseError::GeneralError(e.to_string()))?;
        Self::from_spki(spki)
    }

    pub fn from_spki_pem_file(filename: impl AsRef<Path>) -> Result<Self> {
        let (label, doc) = Document::read_pem_file(filename)
            .map_err(|e| VerificationError::GeneralError(e.to_string()))?;
        SubjectPublicKeyInfoRef::validate_pem_label(&label)
            .map_err(|_| VerificationError::GeneralError("Incorrect PEM label".to_string()))?;
        Self::from_spki_der(doc.as_bytes())
    }

    pub fn from_spki_pem_path_or_base64_der(input: &str) -> Result<Self> {
        // Try as a file path first
        let path = Path::new(input);
        if path.exists() {
            if let Ok(vk) = Self::from_spki_pem_file(path) {
                return Ok(vk);
            }
        }

        // If not a file path or file parsing failed, try as base64 DER
        let bytes = Vec::<u8>::from_base64(input)
            .map_err(|e| ParseError::GeneralError(format!("Invalid base64: {}", e)))?;
        Self::from_spki_der(&bytes)
    }
}

impl TryFrom<CryptoPayload> for VerifyingKey {
    type Error = CryptoError;

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
    type Error = CryptoError;

    fn from_base64<T: AsRef<[u8]>>(base64: T) -> Result<Self> {
        let bytes =
            Vec::<u8>::from_base64(base64).map_err(|e| ParseError::GeneralError(e.to_string()))?;

        match bytes.len() {
            32 => {
                let vk = Ed25519VerifyingKey::try_from(bytes.as_slice()).map_err(|e| {
                    VerificationError::GeneralError(format!("invalid ed25519 key: {}", e))
                })?;
                Ok(VerifyingKey::Ed25519(vk))
            }
            _ => Err(VerificationError::GeneralError(
                "Only Ed25519 keys can be initialized from base64".to_string(),
            )
            .into()),
        }
    }
}

impl TryFrom<String> for VerifyingKey {
    type Error = CryptoError;

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

// // Custom Deserialization of VerifyingKeys

// /// Deserialize a VerifyingKey from a path-like string input
// /// This function can be used with #[serde(deserialize_with = "deserialize_verifying_key_from_path")]
// pub fn from_spki_pem_path<'de, D>(deserializer: D) -> std::result::Result<VerifyingKey, D::Error>
// where
//     D: Deserializer<'de>,
// {
//     let path_str = String::deserialize(deserializer)?;
//     let path = Path::new(&path_str);

//     VerifyingKey::from_spki_pem_file(path).map_err(|e| {
//         D::Error::custom(format!(
//             "Failed to load VerifyingKey from path '{}': {}",
//             path_str, e
//         ))
//     })
// }
