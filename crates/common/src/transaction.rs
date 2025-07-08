use celestia_types::Blob;
use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::binary::{FromBinary, ToBinary};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    errors::TransactionError,
    operation::{Operation, SignatureBundle},
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Represents a partial prism transaction that still needs to be signed.
pub struct UnsignedTransaction {
    /// The account id that this transaction is for
    pub id: String,
    /// The [`Operation`] to be applied to the account
    pub operation: Operation,
    /// The nonce of the account at the time of this transaction
    pub nonce: u64,
}

impl UnsignedTransaction {
    /// Signs the transaction with the given [`SigningKey`] and gives out a full [`Transaction`].
    pub fn sign(self, sk: &SigningKey) -> Result<Transaction, TransactionError> {
        let bytes = self.signing_payload()?;
        let signature = sk.sign(&bytes).map_err(|_| TransactionError::SigningFailed)?;

        Ok(Transaction {
            id: self.id,
            operation: self.operation,
            nonce: self.nonce,
            signature,
            vk: sk.verifying_key(),
        })
    }

    /// Creates a full transaction by adding an externally provided signature.
    /// Can be used to create a transaction that has been signed by an external source,
    /// such as a wallet or a mobile app.
    pub fn externally_signed(self, signature_bundle: SignatureBundle) -> Transaction {
        Transaction {
            id: self.id,
            operation: self.operation,
            nonce: self.nonce,
            signature: signature_bundle.signature,
            vk: signature_bundle.verifying_key,
        }
    }

    /// Returns the transaction's payload that needs to be signed, or a TransactionError if encoding
    /// fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, TransactionError> {
        self.encode_to_bytes().map_err(|e| TransactionError::EncodingFailed(e.to_string()))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
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
    /// Verifies the signature of the transaction
    pub fn verify_signature(&self) -> Result<(), TransactionError> {
        let message = self
            .to_unsigned_tx()
            .encode_to_bytes()
            .map_err(|e| TransactionError::EncodingFailed(e.to_string()))?;

        self.vk
            .verify_signature(&message, &self.signature)
            .map_err(|e| TransactionError::InvalidOp(e.to_string()))
    }

    /// Extracts the part of the transaction that was signed
    fn to_unsigned_tx(&self) -> UnsignedTransaction {
        UnsignedTransaction {
            id: self.id.clone(),
            operation: self.operation.clone(),
            nonce: self.nonce,
        }
    }
}

impl TryFrom<&Blob> for Transaction {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        Transaction::decode_from_bytes(&value.data).map_err(|e| e.into())
    }
}
