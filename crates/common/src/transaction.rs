use anyhow::{anyhow, Result};
use celestia_types::Blob;
use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::binary::{FromBinary, ToBinary};
use serde::{Deserialize, Serialize};

use crate::operation::Operation;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Transaction {
    pub id: String,
    pub operation: Operation,
    pub nonce: u64,
    pub signature: Signature,
    pub vk: VerifyingKey,
}

impl Transaction {
    pub fn get_signature_payload(&self) -> Result<Vec<u8>> {
        let mut tx = self.clone();
        tx.signature = Signature::Placeholder;
        tx.encode_to_bytes().map_err(|e| anyhow!(e))
    }

    pub fn sign(&mut self, sk: &SigningKey) -> Result<Signature> {
        if let Signature::Placeholder = self.signature {
            let sig = sk.sign(&self.get_signature_payload()?);
            self.signature = sig.clone();
            Ok(sig)
        } else {
            Err(anyhow!("Transaction already signed"))
        }
    }
}

impl TryFrom<&Blob> for Transaction {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        Transaction::decode_from_bytes(&value.data).map_err(|e| e.into())
    }
}
