use prism_serde::raw_or_b64;
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use std::path::Path;
use utoipa::ToSchema;

use crate::{CryptoAlgorithm, VerifyingKey};

#[derive(Serialize, Deserialize, ToSchema)]
/// Data structure containing a cryptographic payload with algorithm and bytes
pub struct CryptoPayload {
    /// The cryptographic algorithm to be used
    pub algorithm: CryptoAlgorithm,
    /// The raw bytes of the cryptographic data
    #[schema(
        value_type = String,
        format = Byte,
        example = "jMaZEeHpjIrpO33dkS223jPhurSFixoDJUzNWBAiZKA")]
    #[serde(with = "raw_or_b64")]
    pub bytes: Vec<u8>,
}
