use anyhow::Result;
use serde::{Deserialize, Serialize};

pub trait ToBinary {
    type Error;

    fn encode_to_bytes(&self) -> Result<Vec<u8>, Self::Error>;
}

impl<T> ToBinary for T
where
    T: Serialize,
{
    type Error = bincode::Error;

    fn encode_to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        bincode::serialize(self)
    }
}

pub trait FromBinary: Sized {
    type Error;

    fn decode_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Self::Error>;
}

impl<T> FromBinary for T
where
    T: for<'de> Deserialize<'de>,
{
    type Error = bincode::Error;
    fn decode_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Self::Error> {
        bincode::deserialize(bytes.as_ref())
    }
}
