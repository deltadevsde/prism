use ed25519_dalek::SignatureError;
use indexed_merkle_tree::error::MerkleTreeError;
use thiserror::Error;

// Result alias for [`PrismError`]
pub type PrismResult<T> = Result<T, PrismError>;

#[derive(Error, Debug)]
pub enum PrismError {
    #[error(transparent)]
    General(#[from] GeneralError),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    DataAvailability(#[from] DataAvailabilityError),
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error(transparent)]
    MerkleTree(#[from] MerkleTreeError),
    #[error("config error: {0}")]
    ConfigError(String),
}

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
    #[error(transparent)]
    InvalidSignature(#[from] SignatureError),
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
    #[error("retreiving input order list")]
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
}

// Result alias for [`DataAvailabilityError`]
pub type DAResult<T> = Result<T, DataAvailabilityError>;

#[derive(Error, Debug)]
pub enum DataAvailabilityError {
    #[error("initializing: {0}")]
    InitializationError(String),
    // TODO: is this error needed? doesn't seem to be used anywhere rn
    #[error("establishing connection to da layer: {0}")]
    ConnectionError(String),
    #[error("data channel is closed")]
    ChannelClosed,
    #[error("da networking error: {0}")]
    NetworkError(String),
    #[error("retrieving data at height {0}: {1}")]
    DataRetrievalError(u64, String),
    #[error("submitting epoch {0} to da layer: {1}")]
    SubmissionError(u64, String),
    #[error("setting new sync target: {0}")]
    SyncTargetError(String),
    #[error("receiving message on channel")]
    ChannelReceiveError,
    #[error(transparent)]
    GeneralError(#[from] GeneralError),
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("generating proof: {0}")]
    GenerationError(String),
    #[error("verifying proof: {0}")]
    VerificationError(String),
    #[error("deserializing G1Affine point")]
    G1AffineDeserializationError,
    #[error("unpacking proof components: {0}")]
    ProofUnpackError(String),
    #[error("invalid proof format")]
    InvalidFormatError,
}
