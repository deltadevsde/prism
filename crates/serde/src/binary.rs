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

pub trait FromBinary<'de>: Sized {
    fn decode_from_bytes<B: AsRef<[u8]>>(bytes: &'de B) -> Result<Self>;
}

impl<'de, T> FromBinary<'de> for T
where
    T: Deserialize<'de>,
{
    fn decode_from_bytes<B: AsRef<[u8]>>(bytes: &'de B) -> Result<Self> {
        bincode::deserialize(bytes.as_ref()).map_err(Into::<anyhow::Error>::into)
    }
}
