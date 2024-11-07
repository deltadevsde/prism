use anyhow::{anyhow, Result};
use bls12_381::Scalar;
use jmt::RootHash;
use serde::{Deserialize, Serialize};

use crate::hasher::Hasher;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn hash(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(data.as_ref());
        Self(hasher.finalize())
    }

    pub fn hash_items(items: &[impl AsRef<[u8]>]) -> Self {
        let mut hasher = Hasher::new();
        for item in items {
            hasher.update(item.as_ref());
        }
        Self(hasher.finalize())
    }

    pub const fn zero() -> Self {
        Self([0u8; 32])
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

// implementing it for now to get things to compile, curve choice will be made later
impl TryFrom<Digest> for Scalar {
    type Error = anyhow::Error;

    fn try_from(value: Digest) -> Result<Scalar, Self::Error> {
        let mut byte_array = [0u8; 32];
        byte_array.copy_from_slice(value.as_ref());
        byte_array.reverse();

        let val =
            [
                u64::from_le_bytes(byte_array[0..8].try_into().map_err(|_| {
                    anyhow!(format!("slice to array: [0..8] for digest: {value:?}"))
                })?),
                u64::from_le_bytes(byte_array[8..16].try_into().map_err(|_| {
                    anyhow!(format!("slice to array: [8..16] for digest: {value:?}"))
                })?),
                u64::from_le_bytes(byte_array[16..24].try_into().map_err(|_| {
                    anyhow!(format!("slice to array: [16..24] for digest: {value:?}"))
                })?),
                u64::from_le_bytes(byte_array[24..32].try_into().map_err(|_| {
                    anyhow!(format!("slice to array: [24..32] for digest: {value:?}"))
                })?),
            ];

        Ok(Scalar::from_raw(val))
    }
}

impl From<Digest> for RootHash {
    fn from(val: Digest) -> RootHash {
        RootHash::from(val.0)
    }
}

impl From<RootHash> for Digest {
    fn from(val: RootHash) -> Digest {
        Digest(val.0)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Digest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes)
            .map_err(|e| anyhow!(format!("Invalid Format: {e}")))?;
        Ok(Digest(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}
