use anyhow::Result;
use serde::{Deserialize, Serialize};

pub trait ToBinary {
    fn encode_to_bytes(&self) -> Result<Vec<u8>>;
}

impl<T> ToBinary for T
where
    T: Serialize,
{
    fn encode_to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::<anyhow::Error>::into)
    }
}

pub trait FromBinary: Sized {
    fn decode_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self>;
}

impl<T> FromBinary for T
where
    T: for<'de> Deserialize<'de>,
{
    fn decode_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self> {
        bincode::deserialize(bytes.as_ref()).map_err(Into::<anyhow::Error>::into)
    }
}
