use crate::errors::SignatureError;
use pkcs8::{AlgorithmIdentifierRef, ObjectIdentifier};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
/// Cryptographic algorithm supported by prism.
pub enum CryptoAlgorithm {
    /// Edwards-curve Digital Signature Algorithm (EdDSA) using SHA-512 and Curve25519
    Ed25519,
    /// ECDSA signatures using the secp256k1 curve (used in Bitcoin/Ethereum)
    Secp256k1,
    /// ECDSA signatures using the NIST P-256 curve, also known as prime256v1
    Secp256r1,
    /// Signatures according to ethereum's EIP-191
    Eip191,
    /// Signatures according to Cosmos' ADR-36
    CosmosAdr36,
}

impl CryptoAlgorithm {
    /// Returns a vector containing all variants of `CryptoAlgorithm`.
    pub fn all() -> Vec<Self> {
        vec![
            Self::Ed25519,
            Self::Secp256k1,
            Self::Secp256r1,
            Self::Eip191,
            Self::CosmosAdr36,
        ]
    }
}

impl std::str::FromStr for CryptoAlgorithm {
    type Err = ();

    fn from_str(input: &str) -> Result<CryptoAlgorithm, Self::Err> {
        match input.to_lowercase().as_str() {
            "ed25519" => Ok(CryptoAlgorithm::Ed25519),
            "secp256k1" => Ok(CryptoAlgorithm::Secp256k1),
            "secp256r1" => Ok(CryptoAlgorithm::Secp256r1),
            "eip191" => Ok(CryptoAlgorithm::Eip191),
            "cosmos_adr36" => Ok(CryptoAlgorithm::CosmosAdr36),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
pub const ELLIPTIC_CURVE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub const ECDSA_SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub const SECP256K1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
pub const SECP256R1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

impl<'a> TryFrom<AlgorithmIdentifierRef<'a>> for CryptoAlgorithm {
    type Error = SignatureError;

    fn try_from(algorithm_identifier: AlgorithmIdentifierRef<'a>) -> Result<Self, Self::Error> {
        let oid = algorithm_identifier.oid;

        if oid == ED25519_OID {
            Ok(CryptoAlgorithm::Ed25519)
        } else if oid == ELLIPTIC_CURVE_OID || oid == ECDSA_SHA256_OID {
            let parameter_oid = algorithm_identifier
                .parameters_oid()
                .map_err(|e| SignatureError::AlgorithmError(e.to_string()))?;
            if parameter_oid == SECP256K1_OID {
                Ok(CryptoAlgorithm::Secp256k1)
            } else if parameter_oid == SECP256R1_OID {
                Ok(CryptoAlgorithm::Secp256r1)
            } else {
                return Err(SignatureError::AlgorithmError(
                    "Unsupported elliptic curve OID".to_string(),
                ));
            }
        } else {
            return Err(SignatureError::AlgorithmError(
                "Unsupported algorithm OID".to_string(),
            ));
        }
    }
}
