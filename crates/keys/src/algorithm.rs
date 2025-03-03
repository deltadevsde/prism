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
