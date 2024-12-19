use std::{fmt::Display, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoAlgorithm {
    Ed25519,
    Secp256k1,
    Secp256r1,
}

impl FromStr for CryptoAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ed25519" => Ok(CryptoAlgorithm::Ed25519),
            "secp256k1" => Ok(CryptoAlgorithm::Secp256k1),
            "secp256r1" => Ok(CryptoAlgorithm::Secp256r1),
            _ => Err(anyhow::anyhow!("Invalid crypto algorithm: {}", s)),
        }
    }
}

impl Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoAlgorithm::Ed25519 => write!(f, "ed25519"),
            CryptoAlgorithm::Secp256k1 => write!(f, "secp256k1"),
            CryptoAlgorithm::Secp256r1 => write!(f, "secp256r1"),
        }
    }
}
