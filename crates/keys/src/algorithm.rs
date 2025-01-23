use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum CryptoAlgorithm {
    Ed25519,
    Secp256k1,
    Secp256r1,
}

impl std::str::FromStr for CryptoAlgorithm {
    type Err = ();

    fn from_str(input: &str) -> Result<CryptoAlgorithm, Self::Err> {
        match input.to_lowercase().as_str() {
            "ed25519" => Ok(CryptoAlgorithm::Ed25519),
            "secp256k1" => Ok(CryptoAlgorithm::Secp256k1),
            "secp256r1" => Ok(CryptoAlgorithm::Secp256r1),
            _ => Err(()),
        }
    }
}
