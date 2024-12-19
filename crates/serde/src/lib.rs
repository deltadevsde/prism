pub mod base64;
pub mod binary;
pub mod hex;

pub mod raw_or_hex {
    use std::fmt::Display;

    use crate::hex::{FromHex, ToHex};
    use serde::{self, Deserialize, Deserializer, Serializer};
    use serde_bytes::{Deserialize as BytesDeserialize, Serialize as BytesSerialize};

    pub fn serialize<S, T>(encodable: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ToHex + BytesSerialize,
    {
        if serializer.is_human_readable() {
            let hex_str = encodable.to_hex();
            serializer.serialize_str(&hex_str)
        } else {
            encodable.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromHex + BytesDeserialize<'de>,
        T::Error: Display,
    {
        if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            T::from_hex(hex_str).map_err(serde::de::Error::custom)
        } else {
            T::deserialize(deserializer)
        }
    }
}

pub mod raw_or_b64 {
    use std::fmt::Display;

    use crate::base64::{FromBase64, ToBase64};
    use serde::{self, Deserialize, Deserializer, Serializer};
    use serde_bytes::{Deserialize as BytesDeserialize, Serialize as BytesSerialize};

    pub fn serialize<S, T>(encodable: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ToBase64 + BytesSerialize,
    {
        if serializer.is_human_readable() {
            let base64_string = encodable.to_base64();
            serializer.serialize_str(&base64_string)
        } else {
            encodable.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromBase64 + BytesDeserialize<'de>,
        T::Error: Display,
    {
        if deserializer.is_human_readable() {
            let base64_string = String::deserialize(deserializer)?;
            T::from_base64(base64_string).map_err(serde::de::Error::custom)
        } else {
            T::deserialize(deserializer)
        }
    }
}
