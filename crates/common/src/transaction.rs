use anyhow::{anyhow, Result};
use celestia_types::Blob;
use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::binary::{FromBinary, ToBinary};
use serde::{Deserialize, Serialize};

use crate::operation::Operation;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Represents a prism transaction that can be applied to an account.
pub struct Transaction {
    /// The account id that this transaction is for
    pub id: String,
    /// The [`Operation`] to be applied to the account
    pub operation: Operation,
    /// The nonce of the account at the time of this transaction
    pub nonce: u64,
    /// The signature of the transaction, signed by [`self::vk`].
    pub signature: Signature,
    /// The verifying key of the signer of this transaction. This vk must be
    /// included in the account's valid_keys set.
    pub vk: VerifyingKey,
}

impl Transaction {
    /// Encodes the transaction to bytes to prepare for signing.
    pub fn get_signature_payload(&self) -> Result<Vec<u8>> {
        let mut tx = self.clone();
        tx.signature = Signature::Placeholder;
        tx.encode_to_bytes().map_err(|e| anyhow!(e))
    }

    /// Signs the transaction with the given [`SigningKey`] and inserts the
    /// signature into the transaction.
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
