mod signatures;
mod signing_keys;
mod verifying_keys;

pub use signatures::*;
pub use signing_keys::*;
pub use verifying_keys::*;

use std::str::FromStr;
use std::fmt;
use std::clone::Clone;

#[derive(Debug, Clone, Copy)]
pub enum KeyAlgorithm {
    Ed25519,
    Secp256k1,
    Secp256r1,
    Placeholder,
}

impl FromStr for KeyAlgorithm {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<KeyAlgorithm, Self::Err> {
        match input.to_lowercase().as_str() {
            "ed25519" => Ok(KeyAlgorithm::Ed25519),
            "secp256k1" => Ok(KeyAlgorithm::Secp256k1),
            "secp256r1" => Ok(KeyAlgorithm::Secp256r1),
            "placeholder" => Ok(KeyAlgorithm::Placeholder),
            _ => Err(anyhow::anyhow!("Invalid algorithm: {}", input)),
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyAlgorithm::Ed25519 => write!(f, "Ed25519"),
            KeyAlgorithm::Secp256k1 => write!(f, "Secp256k1"),
            KeyAlgorithm::Secp256r1 => write!(f, "Secp256r1"),
            KeyAlgorithm::Placeholder => write!(f, "Placeholder"),
        }
    }
}

#[cfg(test)]
mod tests;
