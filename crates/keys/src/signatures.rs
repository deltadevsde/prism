use ed25519_consensus::Signature as Ed25519Signature;
use k256::ecdsa::Signature as Secp256k1Signature;
use p256::ecdsa::Signature as Secp256r1Signature;
use pkcs8::{
    AlgorithmIdentifierRef, SecretDocument,
    der::{Decode, asn1::OctetStringRef, zeroize::Zeroize},
};
use prism_serde::base64::ToBase64;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    result::Result,
};
use thiserror::Error;
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{RefOr, Schema},
};

use crate::{
    CryptoAlgorithm, ECDSA_SHA256_OID, ED25519_OID, SECP256K1_OID, SECP256R1_OID,
    der::SignatureInfoRef, payload::CryptoPayload,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(try_from = "CryptoPayload", into = "CryptoPayload")]
pub enum Signature {
    Secp256k1(Secp256k1Signature),
    Ed25519(Ed25519Signature),
    Secp256r1(Secp256r1Signature),
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(sig) => sig.to_bytes().to_vec(),
            Signature::Secp256k1(sig) => sig.to_vec(),
            Signature::Secp256r1(sig) => sig.to_vec(),
        }
    }

    pub fn from_algorithm_and_bytes(
        algorithm: CryptoAlgorithm,
        bytes: &[u8],
    ) -> Result<Self, SignatureError> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => Ed25519Signature::try_from(bytes)
                .map(Signature::Ed25519)
                .map_err(|e| SignatureError::AlgorithmError(e.to_string())),
            CryptoAlgorithm::Secp256k1 => Secp256k1Signature::from_slice(bytes)
                .map(Signature::Secp256k1)
                .map_err(|e| SignatureError::AlgorithmError(e.to_string())),
            CryptoAlgorithm::Secp256r1 => Secp256r1Signature::from_slice(bytes)
                .map(Signature::Secp256r1)
                .map_err(|e| SignatureError::AlgorithmError(e.to_string())),
            CryptoAlgorithm::Eip191 => Err(SignatureError::EipSignatureError),
            CryptoAlgorithm::CosmosAdr36 => Err(SignatureError::AdrSignatureError),
        }
    }

    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            Signature::Ed25519(_) => CryptoAlgorithm::Ed25519,
            Signature::Secp256k1(_) => CryptoAlgorithm::Secp256k1,
            Signature::Secp256r1(_) => CryptoAlgorithm::Secp256r1,
        }
    }

    fn algorithm_identifier(&self) -> AlgorithmIdentifierRef {
        match self {
            Signature::Ed25519(_) => AlgorithmIdentifierRef {
                oid: ED25519_OID,
                parameters: None,
            },
            Signature::Secp256k1(_) => AlgorithmIdentifierRef {
                oid: ECDSA_SHA256_OID,
                parameters: Some((&SECP256K1_OID).into()),
            },
            Signature::Secp256r1(_) => AlgorithmIdentifierRef {
                oid: ECDSA_SHA256_OID,
                parameters: Some((&SECP256R1_OID).into()),
            },
        }
    }

    pub fn to_prism_der(&self) -> Result<Vec<u8>, SignatureError> {
        let signature_bytes = self.to_bytes();
        let mut der_bytes = Vec::with_capacity(2 + signature_bytes.len());

        der_bytes.push(0x04); // octet stream
        der_bytes.push(
            signature_bytes
                .len()
                .try_into()
                .map_err(|_| SignatureError::AlgorithmError("Map conversion failed".to_string()))?,
        ); // length of signature bytes
        der_bytes.extend_from_slice(&signature_bytes);

        let signature_info = SignatureInfoRef {
            algorithm: self.algorithm_identifier(),
            signature: OctetStringRef::new(&der_bytes)
                .map_err(|e| SignatureError::AlgorithmError(e.to_string()))?,
        };

        let doc = SecretDocument::encode_msg(&signature_info)
            .map_err(|e| SignatureError::AlgorithmError(e.to_string()))?;
        der_bytes.zeroize();
        Ok(doc.as_bytes().to_vec())
    }

    pub fn from_prism_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        let signature_info = SignatureInfoRef::from_der(bytes)
            .map_err(|e| SignatureError::AlgorithmError(e.to_string()))?;
        let algorithm = CryptoAlgorithm::try_from(signature_info.algorithm)
            .map_err(|e| SignatureError::AlgorithmError(e.to_string()))?;

        // Signature byte representation:
        // 1st byte: 0x04 (type OCTET STRING)
        // 2nd byte: length of the signature
        // rest: signature bytes
        match signature_info.signature.as_bytes() {
            [0x04, _, signature_bytes @ ..] => {
                Signature::from_algorithm_and_bytes(algorithm, signature_bytes)
            }
            _ => Err(SignatureError::MalformedSignError),
        }
    }
}

impl TryFrom<CryptoPayload> for Signature {
    type Error = SignatureError;

    fn try_from(value: CryptoPayload) -> std::result::Result<Self, Self::Error> {
        Signature::from_algorithm_and_bytes(value.algorithm, &value.bytes)
    }
}

impl From<Signature> for CryptoPayload {
    fn from(signature: Signature) -> Self {
        CryptoPayload {
            algorithm: signature.algorithm(),
            bytes: signature.to_bytes(),
        }
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let encoded = self.to_bytes().to_base64();
        write!(f, "{}", encoded)
    }
}

/// Necessary to represent `Signature` as `CryptoPayload` in the OpenAPI spec.
/// Workaround, because `schema(as = CryptoPayload)` currently requires all wrapped
/// native signature types in the enum variants to implement `ToSchema` as well.
impl ToSchema for Signature {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("CryptoPayload")
    }

    fn schemas(_schemas: &mut Vec<(String, RefOr<Schema>)>) {
        CryptoPayload::schemas(_schemas);
    }
}

impl PartialSchema for Signature {
    fn schema() -> RefOr<Schema> {
        CryptoPayload::schema()
    }
}

#[derive(Error, Clone, Debug)]
pub enum SignatureError {
    #[error("No EIP-191 specific signatures implemented")]
    EipSignatureError,
    #[error("No ADR-36 specific signatures implemented")]
    AdrSignatureError,
    #[error("malformed signature")]
    MalformedSignError,
    #[error("Algorithm Error {0}")]
    AlgorithmError(String),
}
