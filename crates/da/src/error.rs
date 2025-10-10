use thiserror::Error;

#[derive(Error, Debug)]
pub enum DataAvailabilityError {
    #[error("Failed to initialize DA: {0}")]
    InitializationError(String),
    #[error("data channel is closed")]
    ChannelClosed,
    #[error("da networking error: {0}")]
    NetworkError(String),
    #[error("retrieving data at height {0}: {1}")]
    DataRetrievalError(u64, String),
    #[error("Submission to DA failed: {0}")]
    SubmissionError(String),
    #[error("setting new sync target: {0}")]
    SyncTargetError(String),
    #[error("receiving message on channel")]
    ChannelReceiveError,
    #[error("shutdown error: {0}")]
    ShutdownError(String),
    #[error(transparent)]
    EpochVerification(#[from] EpochVerificationError),
}

#[derive(Error, Debug)]
pub enum EpochVerificationError {
    #[error("public values too short, has length {0}")]
    InvalidPublicValues(usize),
    #[error("commitment error: {0}")]
    CommitmentError(#[from] CommitmentError),
    #[error("signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("failed to decode finalized epoch from blob")]
    DecodingError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("epoch proof verification error: {0}")]
    ProofVerificationError(String),
}

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("invalid length")]
    InvalidLength,
    #[error("missing signature")]
    MissingSignature,
    #[error("decoding error: {0}")]
    DecodingError(String),
    #[error("verification error: {0}")]
    VerificationError(String),
    #[error("signing error: {0}")]
    SigningError(String),
}

#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("previous commitment mismatch")]
    PreviousCommitmentMismatch,
    #[error("current commitment mismatch")]
    CurrentCommitmentMismatch,
}
