use thiserror::Error;

// general reusable errors
#[derive(Error, Debug)]
pub enum GeneralError {
    #[error("parsing: {0}")]
    ParsingError(String),
    #[error("creating blob object: {0}")]
    BlobCreationError(String),
    #[error("encoding: {0}")]
    EncodingError(String),
    #[error("decoding: {0}")]
    DecodingError(String),
    #[error("missing argument: {0}")]
    MissingArgumentError(String),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("starting webserver")]
    WebserverError,
    #[error("initializing service: {0}")]
    InitializationError(String),
}

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("acquiring database lock")]
    LockError,
    #[error("retrieving keys from {0} dictionary")]
    KeysError(String),
    #[error("{0} not found")]
    NotFoundError(String),
    #[error("retrieving input order list")]
    GetInputOrderError,
    #[error("reading {0} from database")]
    ReadError(String),
    #[error("writing {0} to database")]
    WriteError(String),
    #[error("deleting {0} from database")]
    DeleteError(String),
    #[error(transparent)]
    GeneralError(#[from] GeneralError),
    #[error("connecting to database: {0}")]
    ConnectionError(String),
    #[error("initializing database: {0}")]
    InitializationError(String),
    #[error("parsing error: {0}")]
    ParsingError(String),
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("service proof is missing from batch for create account verification: {0}")]
    MissingServiceProof(String),
    #[error("service challenge is missing for create account verification: {0}")]
    MissingServiceChallenge(String),
    #[error("encoding error: {0}")]
    EncodingError(String),
    #[error("account update error: {0}")]
    AccountError(String),
    #[error("proof verification error: {0}")]
    VerificationError(String),
    #[error("existence error: {0}")]
    ExistenceError(String),
    #[error("nonexistence error: {0}")]
    NonexistenceError(String),
    #[error("Transaction error: {0}")]
    TransactionError(String),
}

impl From<bincode::Error> for ProofError {
    fn from(err: bincode::Error) -> Self {
        ProofError::EncodingError(err.to_string())
    }
}

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
