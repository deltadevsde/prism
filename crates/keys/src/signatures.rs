use anyhow::{bail, Result};
use ed25519_consensus::Signature as Ed25519Signature;
use p256::ecdsa::Signature as Secp256r1Signature;
use secp256k1::ecdsa::Signature as Secp256k1Signature;

use crate::KeyAlgorithm;
use prism_serde::CryptoPayload;
use serde::{Deserialize, Serialize};
use std::{self, str::FromStr};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(try_from = "CryptoPayload", into = "CryptoPayload")]
pub enum Signature {
    Secp256k1(Secp256k1Signature),
    Ed25519(Ed25519Signature),
    Secp256r1(Secp256r1Signature),
    #[default]
    Placeholder,
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(sig) => sig.to_bytes().to_vec(),
            Signature::Secp256k1(sig) => sig.serialize_der().to_vec(),
            Signature::Secp256r1(sig) => sig.to_der().as_bytes().to_vec(),
            Signature::Placeholder => vec![],
        }
    }

    pub fn from_algorithm_and_bytes(algorithm: KeyAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            KeyAlgorithm::Ed25519 => {
                Ed25519Signature::try_from(bytes).map(Signature::Ed25519).map_err(|e| e.into())
            }
            KeyAlgorithm::Secp256k1 => {
                Secp256k1Signature::from_der(bytes).map(Signature::Secp256k1).map_err(|e| e.into())
            }
            KeyAlgorithm::Secp256r1 => {
                Secp256r1Signature::from_der(bytes).map(Signature::Secp256r1).map_err(|e| e.into())
            }
            _ => bail!("Unexpected algorithm for Signature: {}", algorithm),
        }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Signature::Ed25519(_) => KeyAlgorithm::Ed25519,
            Signature::Secp256k1(_) => KeyAlgorithm::Secp256k1,
            Signature::Secp256r1(_) => KeyAlgorithm::Secp256r1,
            Signature::Placeholder => KeyAlgorithm::Placeholder,
        }
    }
}

impl TryFrom<CryptoPayload> for Signature {
    type Error = anyhow::Error;

    fn try_from(value: CryptoPayload) -> std::result::Result<Self, Self::Error> {
        Signature::from_algorithm_and_bytes(KeyAlgorithm::from_str(&value.algorithm)?, &value.bytes)
    }
}

impl From<Signature> for CryptoPayload {
    fn from(signature: Signature) -> Self {
        CryptoPayload {
            algorithm: signature.algorithm().to_string(),
            bytes: signature.to_bytes(),
        }
    }
}
