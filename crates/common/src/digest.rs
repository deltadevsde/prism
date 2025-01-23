use anyhow::Result;
use serde::{Deserialize, Serialize};

use prism_serde::{
    base64::FromBase64,
    hex::{FromHex, ToHex},
    raw_or_hex,
};
use sha2::{Digest as _, Sha256};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy, ToSchema)]
pub struct Digest(#[serde(with = "raw_or_hex")] pub [u8; 32]);

impl Digest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    pub fn hash(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data.as_ref());
        Self(hasher.finalize().into())
    }

    pub fn hash_items(items: &[impl AsRef<[u8]>]) -> Self {
        let mut hasher = Sha256::new();
        for item in items {
            hasher.update(item.as_ref());
        }
        Self(hasher.finalize().into())
    }

    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

// serializer and deserializer for rocksdb
// converts from bytearrays into digests
// padds it with zero if it is too small
impl<const N: usize> From<[u8; N]> for Digest {
    fn from(value: [u8; N]) -> Self {
        assert!(N <= 32, "Input array must not exceed 32 bytes");
        let mut digest = [0u8; 32];
        digest[..N].copy_from_slice(&value);
        Self(digest)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for Digest {
    type Error = anyhow::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> std::result::Result<Self, Self::Error> {
        Ok(Self(<[u8; 32]>::from_hex(hex)?))
    }
}

impl FromBase64 for Digest {
    type Error = anyhow::Error;

    fn from_base64<T: AsRef<[u8]>>(base64: T) -> Result<Self, Self::Error> {
        Ok(Self(<[u8; 32]>::from_base64(base64)?))
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
