use thiserror::Error;

pub type Result<G> = std::result::Result<G, CryptoError>;

#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("Parse error: {0}")]
    ParseError(#[from] ParseError),

    #[error("Verification error: {0}")]
    VerificationError(#[from] VerificationError),
}

#[derive(Error, Clone, Debug)]
pub enum SignatureError {
    #[error("No {0} specific signatures implemented")]
    UnsupportedFormatError(String),

    #[error("Malformed signature")]
    MalformedSignError,

    #[error("Algorithm Error: {0}")]
    AlgorithmError(String),

    #[error("Invalid signature type")]
    InvalidSignError,

    #[error("Signing operation failed: {0}")]
    SigningError(String),

    #[error("Cosmos Error: {0}")]
    CosmosError(String),
}

#[derive(Error, Clone, Debug)]
pub enum ParseError {
    #[error("Creating PKCS8 DER failed")]
    DerCreationError,

    #[error("Creating PKCS8 PEM failed")]
    PemCreationError,

    #[error("Parsing key algorithm from PKCS#8 DER failed")]
    DerParseError,

    #[error("Invalid PEM label")]
    PemLabelError,

    #[error("Invalid key bytes for algorithm: {0}")]
    InvalidKeyBytes(String),

    #[error("A parsing error occurred: {0}")]
    GeneralError(String),
}

#[derive(Error, Clone, Debug)]
pub enum VerificationError {
    #[error("Failed to verify {0} signature: {1}")]
    VerifyError(String, String),

    #[error("Verifying key for {0} can only verify secp256k1 signatures")]
    SignatureError(String),

    #[error("Creating {0} failed")]
    VKCreationError(String),

    #[error("{0} vk from DER format failed: {1}")]
    IntoRefError(String, String),

    #[error("{0} vk {1} DER format is not implemented")]
    NotImplementedError(String, String),

    #[error("A verification error occurred: {0}")]
    GeneralError(String),
}
