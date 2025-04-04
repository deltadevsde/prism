use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};

use anyhow::{Result, bail};
use ed25519_consensus::Signature as Ed25519Signature;
use k256::ecdsa::Signature as Secp256k1Signature;
use p256::ecdsa::Signature as Secp256r1Signature;

use prism_serde::base64::ToBase64;
use serde::{Deserialize, Serialize};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{RefOr, Schema},
};

use crate::{CryptoAlgorithm, payload::CryptoPayload};

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

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let der = match self {
            Signature::Ed25519(_) => bail!("Ed25519 sig from DER format is not implemented"),
            Signature::Secp256k1(sig) => sig.to_der().as_bytes().to_vec(),
            Signature::Secp256r1(sig) => sig.to_der().as_bytes().to_vec(),
        };
        Ok(der)
    }

    pub fn from_algorithm_and_bytes(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => {
                Ed25519Signature::try_from(bytes).map(Signature::Ed25519).map_err(|e| e.into())
            }
            CryptoAlgorithm::Secp256k1 => Secp256k1Signature::from_slice(bytes)
                .map(Signature::Secp256k1)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Secp256r1 => Secp256r1Signature::from_slice(bytes)
                .map(Signature::Secp256r1)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Eip191 => bail!("No EIP-191 specific signatures implemented"),
            CryptoAlgorithm::CosmosAdr36 => {
                bail!("No cosmos ADR-36 specific signatures implemented")
            }
        }
    }

    pub fn from_algorithm_and_der(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => bail!("Ed25519 sig from DER format is not implemented"),
            CryptoAlgorithm::Secp256k1 => {
                Secp256k1Signature::from_der(bytes).map(Signature::Secp256k1).map_err(|e| e.into())
            }
            CryptoAlgorithm::Secp256r1 => {
                Secp256r1Signature::from_der(bytes).map(Signature::Secp256r1).map_err(|e| e.into())
            }
            CryptoAlgorithm::Eip191 => bail!("No EIP-191 specific signatures implemented"),
            CryptoAlgorithm::CosmosAdr36 => {
                bail!("No cosmos ADR-36 specific signatures implemented")
            }
        }
    }

    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            Signature::Ed25519(_) => CryptoAlgorithm::Ed25519,
            Signature::Secp256k1(_) => CryptoAlgorithm::Secp256k1,
            Signature::Secp256r1(_) => CryptoAlgorithm::Secp256r1,
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
