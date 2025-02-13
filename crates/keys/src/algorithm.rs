use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
/// Cryptographic algorithm supported by prism.
pub enum CryptoAlgorithm {
    /// Edwards-curve Digital Signature Algorithm (EdDSA) using SHA-512 and Curve25519
    Ed25519,
    #[cfg(not(target_arch = "wasm32"))]
    /// ECDSA signatures using the secp256k1 curve (used in Bitcoin/Ethereum)
    Secp256k1,
    /// ECDSA signatures using the NIST P-256 curve, also known as prime256v1
    Secp256r1,
}

impl std::str::FromStr for CryptoAlgorithm {
    type Err = ();

    fn from_str(input: &str) -> Result<CryptoAlgorithm, Self::Err> {
        match input.to_lowercase().as_str() {
            "ed25519" => Ok(CryptoAlgorithm::Ed25519),
            #[cfg(not(target_arch = "wasm32"))]
            "secp256k1" => Ok(CryptoAlgorithm::Secp256k1),
            "secp256r1" => Ok(CryptoAlgorithm::Secp256r1),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
