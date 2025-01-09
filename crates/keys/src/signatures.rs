use anyhow::Result;
use ed25519_consensus::Signature as Ed25519Signature;
use p256::ecdsa::Signature as Secp256r1Signature;
use secp256k1::ecdsa::Signature as Secp256k1Signature;

use serde::{Deserialize, Serialize};

use crate::{payload::CryptoPayload, CryptoAlgorithm};

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

    pub fn from_algorithm_and_bytes(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => {
                Ed25519Signature::try_from(bytes).map(Signature::Ed25519).map_err(|e| e.into())
            }
            CryptoAlgorithm::Secp256k1 => {
                Secp256k1Signature::from_der(bytes).map(Signature::Secp256k1).map_err(|e| e.into())
            }
            CryptoAlgorithm::Secp256r1 => {
                Secp256r1Signature::from_der(bytes).map(Signature::Secp256r1).map_err(|e| e.into())
            }
        }
    }

    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            Signature::Ed25519(_) => CryptoAlgorithm::Ed25519,
            Signature::Secp256k1(_) => CryptoAlgorithm::Secp256k1,
            Signature::Secp256r1(_) => CryptoAlgorithm::Secp256r1,
            Signature::Placeholder => CryptoAlgorithm::Ed25519,
        }
    }
}

impl TryFrom<CryptoPayload> for Signature {
    type Error = anyhow::Error;

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
