use ed25519::Signature;
use anyhow::Result;


pub trait SignedContent {
    fn get_signature(&self) -> Result<Signature>;
    fn get_plaintext(&self) -> Result<Vec<u8>>;
    fn get_public_key(&self) -> Result<String>;
}

