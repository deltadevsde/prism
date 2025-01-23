use prism_serde::raw_or_b64;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::CryptoAlgorithm;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CryptoPayload {
    pub algorithm: CryptoAlgorithm,
    #[serde(with = "raw_or_b64")]
    pub bytes: Vec<u8>,
}
