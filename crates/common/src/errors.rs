use thiserror::Error;

#[derive(Error, Clone, Debug)]
pub enum OperationError {
    #[error("id cannot be empty when registering service")]
    EmptyServiceId,
    #[error("id cannot be empty when creating account")]
    EmptyAccountId,
    #[error("service_id cannot be empty when creating account")]
    EmptyServiceIdForAccount,
    #[error("data size {0} exceeds maximum allowed size")]
    DataTooLarge(usize),
}

#[derive(Error, Clone, Debug)]
pub enum TransactionError {
    #[error("invalid operation: {0}")]
    InvalidOp(String),
    #[error("invalid nonce: {0}")]
    InvalidNonce(u64),
    #[error("missing account's public key")]
    MissingKey,
    #[error("encoding failed with: {0}")]
    EncodingFailed(String),
    #[error("signing failed")]
    SigningFailed,
    #[error("missing sender")]
    MissingSender,
}

#[derive(Error, Clone, Debug)]
pub enum AccountError {
    #[error("nonce doesn't match: {0} != {1}")]
    NonceError(u64, u64),
    #[error("transaction id doesn't match operation id: {0} != {1}")]
    AccountIdError(String, String),
    #[error("transaction key doesn't match operation key")]
    AccountKeyError(String, String),
    #[error("transaction id doesn't match account id: {0} != {1}")]
    TransactionIdError(String, String),
    #[error("invalid key")]
    InvalidKey,
    #[error("transaction error: {0}")]
    TransactionError(#[from] TransactionError),
}
