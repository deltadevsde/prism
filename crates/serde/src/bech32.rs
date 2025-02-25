use bech32::{Bech32, DecodeError, EncodeError, Hrp};

pub trait ToBech32 {
    type Error;
    fn to_bech32(&self, hrp: &str) -> Result<String, Self::Error>;
}

impl<T> ToBech32 for T
where
    T: AsRef<[u8]>,
{
    type Error = EncodeError;

    fn to_bech32(&self, hrp: &str) -> Result<String, Self::Error> {
        let hrp = Hrp::parse_unchecked(hrp);
        bech32::encode::<Bech32>(hrp, self.as_ref())
    }
}

pub trait FromBech32: Sized {
    type Error;

    fn from_bech32(bech32: &str) -> Result<Self, Self::Error>;
}

impl FromBech32 for Vec<u8> {
    type Error = DecodeError;

    fn from_bech32(bech32: &str) -> Result<Self, Self::Error> {
        let (_, data) = bech32::decode(bech32)?;
        Ok(data)
    }
}
