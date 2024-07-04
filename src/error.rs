use indexed_merkle_tree::error::MerkleTreeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DeimosError {
    #[error("General error: {0}")]
    General(GeneralError),
    #[error("Database error: {0}")]
    Database(DatabaseError),
    #[error("Data availability error: {0}")]
    DataAvailability(DataAvailabilityError),
    #[error("Proof error: {0}")]
    Proof(ProofError),
    #[error("Merkle tree error: {0}")]
    MerkleTree(MerkleTreeError),
}

// general reusable errors
#[derive(Error, Debug)]
pub enum GeneralError {
    #[error("Parsing error: {0}")]
    ParsingError(String),
    #[error("Failed to create Blob object")]
    BlobCreationError,
    #[error("Hexadecimal decoding error: {0}")]
    HexDecodingError(String),
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Decoding error: {0}")]
    DecodingError(String),
    #[error("Required argument missing")]
    MissingArgumentError,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Failed to start webserver")]
    WebserverError,
}

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Failed to acquire lock on the Database connection")]
    LockError,
    #[error("Failed to retrieve keys from {0} dictionary from the Database database")]
    KeysError(String),
    #[error("{0} not found")]
    NotFoundError(String),
    #[error("Failed to retrieve the input order list from the Database database")]
    GetInputOrderError,
    #[error("Failed to write {0} to the Database database")]
    WriteError(String),
    #[error("Failed to delete {0} from the Database database")]
    DeleteError(String),
}

#[derive(Error, Debug)]
pub enum DataAvailabilityError {
    #[error("Initialization error: {0}")]
    InitializationError(String),
    // TODO: is this error needed? doesn't seem to be used anywhere rn
    #[error("Failed to establish connection: {0}")]
    ConnectionError(String),
    #[error("The data channel has been closed")]
    ChannelClosed,
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Data retrieval error at height {0}: {1}")]
    DataRetrievalError(u64, String),
    #[error("Error submitting data at height {0}: {1}")]
    SubmissionError(u64, String),
    #[error("Error {0} new sync target: {1}")]
    SyncTargetError(String, String),
    #[error("Error receiving message from channel")]
    ChannelReceiveError,
    #[error("General Deimos error: {0}")]
    GeneralError(#[from] GeneralError),
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Failed to generate proof")]
    GenerationError,
    #[error("Failed to verify proof")]
    VerificationError,
    #[error("Failed to deserialize G1Affine point")]
    G1AffineDeserializationError,
    #[error("Failed to unpack proof components")]
    ProofUnpackError,
    #[error("Invalid proof format")]
    InvalidFormatError,
}
