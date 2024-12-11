use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

impl<T> ToBase64 for T
where
    T: AsRef<[u8]>,
{
    fn to_base64(&self) -> String {
        BASE64.encode(self)
    }
}

pub trait FromBase64: Sized {
    type Error;

    fn from_base64<T: AsRef<[u8]>>(base64: T) -> Result<Self, Self::Error>;
}

impl FromBase64 for Vec<u8> {
    type Error = anyhow::Error;

    fn from_base64<T: AsRef<[u8]>>(base64: T) -> Result<Self> {
        BASE64.decode(base64).map_err(|e| e.into())
    }
}

impl FromBase64 for [u8; 32] {
    type Error = anyhow::Error;

    fn from_base64<T: AsRef<[u8]>>(base64: T) -> Result<Self> {
        let mut output = [0u8; 32];
        BASE64.decode_slice(base64, &mut output)?;
        Ok(output)
    }
}
