use std::fmt::{Display, Formatter};

use anyhow::{anyhow, Result};
use celestia_types::Blob;
use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::binary::{FromBinary, ToBinary};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::operation::Operation;

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
        let bytes = self.encode_to_bytes().map_err(|_| TransactionError::EncodingFailed)?;
        let signature = sk.sign(&bytes);

        Ok(Transaction {
            id: self.id,
            operation: self.operation,
            nonce: self.nonce,
            signature,
            vk: sk.verifying_key(),
        })
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
    pub fn verify_signature(&self) -> Result<()> {
        let message = self.to_unsigned_tx().encode_to_bytes()?;
        self.vk.verify_signature(&message, &self.signature)
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

#[derive(Debug)]
pub enum TransactionError {
    InvalidOp(String),
    InvalidNonce(u64),
    MissingKey,
    EncodingFailed,
    SigningFailed,
    MissingSender,
}

impl Display for TransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionError::InvalidOp(msg) => write!(f, "Invalid operation: {}", msg),
            TransactionError::InvalidNonce(nonce) => write!(f, "Invalid nonce: {}", nonce),
            TransactionError::MissingKey => write!(f, "Public Key for account is missing"),
            TransactionError::EncodingFailed => write!(f, "Encoding transaction failed"),
            TransactionError::SigningFailed => write!(f, "Signing transaction failed"),
            TransactionError::MissingSender => write!(f, "Sender for transaction is missing"),
        }
    }
}

impl From<TransactionError> for anyhow::Error {
    fn from(error: TransactionError) -> Self {
        anyhow!(error.to_string())
    }
}
