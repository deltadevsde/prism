#![allow(dead_code)]

pub mod binary;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CryptoPayload {
    pub algorithm: String,
    #[serde(with = "raw_or_b64")]
    pub bytes: Vec<u8>,
}

pub mod raw_or_hex {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S, T: AsRef<[u8]>>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let hex_str = hex::encode(bytes.as_ref());
            serializer.serialize_str(&hex_str)
        } else {
            serializer.serialize_bytes(bytes.as_ref())
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            hex::decode(hex_str.as_bytes()).map_err(serde::de::Error::custom)
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
}

pub mod raw_or_hex_fixed {
    use super::raw_or_hex;
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        raw_or_hex::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = raw_or_hex::deserialize(deserializer)?;

        let len = vec.len();
        vec.try_into()
            .map_err(|_| serde::de::Error::custom(format!("Expected {} bytes, got {}", N, len)))
    }
}

pub mod raw_or_b64 {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S, T: AsRef<[u8]>>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let base64_string = BASE64.encode(bytes.as_ref());
            serializer.serialize_str(&base64_string)
        } else {
            serializer.serialize_bytes(bytes.as_ref())
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let base64_string = String::deserialize(deserializer)?;
            BASE64.decode(base64_string.as_bytes()).map_err(serde::de::Error::custom)
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
}

pub mod raw_or_b64_fixed {
    use super::raw_or_b64;
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        raw_or_b64::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = raw_or_b64::deserialize(deserializer)?;

        let len = vec.len();
        vec.try_into()
            .map_err(|_| serde::de::Error::custom(format!("Expected {} bytes, got {}", N, len)))
    }
}
