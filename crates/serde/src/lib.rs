pub mod base64;
pub mod binary;
pub mod hex;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CryptoPayload {
    pub algorithm: String,
    #[serde(with = "raw_or_b64")]
    pub bytes: Vec<u8>,
}

pub mod raw_or_hex {
    use std::fmt::Display;

    use serde::{self, Deserialize, Deserializer, Serializer};

    use crate::hex::{FromHex, ToHex};

    pub fn serialize<S, T>(encodable: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ToHex + AsRef<[u8]>,
    {
        if serializer.is_human_readable() {
            let hex_str = encodable.to_hex();
            serializer.serialize_str(&hex_str)
        } else {
            serializer.serialize_bytes(encodable.as_ref())
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromHex + Deserialize<'de>,
        T::Error: Display,
    {
        if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            T::from_hex(hex_str).map_err(serde::de::Error::custom)
        } else {
            Deserialize::deserialize(deserializer)
        }
    }
}

pub mod raw_or_b64 {
    use crate::base64::{FromBase64, ToBase64};
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::fmt::Display;

    pub fn serialize<S, T: AsRef<[u8]>>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let base64_string = bytes.to_base64();
            serializer.serialize_str(&base64_string)
        } else {
            serializer.serialize_bytes(bytes.as_ref())
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromBase64 + Deserialize<'de>,
        T::Error: Display,
    {
        if deserializer.is_human_readable() {
            let base64_string = String::deserialize(deserializer)?;
            T::from_base64(base64_string).map_err(serde::de::Error::custom)
        } else {
            Deserialize::deserialize(deserializer)
        }
    }
}
