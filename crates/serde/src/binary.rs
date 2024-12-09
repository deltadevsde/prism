use anyhow::Result;
use serde::{Deserialize, Serialize};

pub trait BinaryTranscodable<'de>: Sized {
    fn encode_to_bytes(&self) -> Result<Vec<u8>>;
    fn decode_from_bytes<B: AsRef<[u8]>>(bytes: &'de B) -> Result<Self>;
}

impl<'de, T> BinaryTranscodable<'de> for T
where
    T: Serialize + Deserialize<'de>,
{
    fn encode_to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::<anyhow::Error>::into)
    }

    fn decode_from_bytes<B: AsRef<[u8]>>(bytes: &'de B) -> Result<Self> {
        bincode::deserialize(bytes.as_ref()).map_err(Into::<anyhow::Error>::into)
    }
}
