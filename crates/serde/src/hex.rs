use anyhow::Result;

pub trait ToHex {
    fn to_hex(&self) -> String;
}

impl<T> ToHex for T
where
    T: hex::ToHex,
{
    fn to_hex(&self) -> String {
        self.encode_hex()
    }
}

pub trait FromHex: Sized {
    type Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error>;
}

impl<T> FromHex for T
where
    T: hex::FromHex,
{
    type Error = T::Error;

    fn from_hex<U: AsRef<[u8]>>(hex: U) -> Result<Self, Self::Error> {
        T::from_hex(hex)
    }
}
