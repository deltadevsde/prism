use thiserror::Error;

pub type Result<G> = std::result::Result<G, CryptoError>;

// Top-level error type
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    #[error("signature error: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("keys error: {0}")]
    KeysError(#[from] KeysError),

    #[error("verification error: {0}")]
    VerificationError(#[from] VerificationError),
}

#[derive(Error, Clone, Debug)]
pub enum SignatureError {
    #[error("No EIP-191 specific signatures implemented")]
    EipSignatureError,
    #[error("No ADR-36 specific signatures implemented")]
    AdrSignatureError,
    #[error("Malformed signature")]
    MalformedSignError,
    #[error("Algorithm Error: {0}")]
    AlgorithmError(String),
    #[error("Something went wrong: {0}")]
    CosmosError(String),
}

#[derive(Error, Clone, Debug)]
pub enum KeysError {
    #[error("Creating PKCS8 DER failed")]
    DerCreationError,
    #[error("Creating PKCS8 PEM failed")]
    PemCreationError,
    #[error("Parsing key algorithm from PKCS#8 DER failed")]
    ParseError,
    #[error("Invalid PEM label")]
    PemLabelError,
    #[error("Invalid key bytes for algorithm: {0}")]
    InvalidKeyBytes(String),
    #[error("Signing operation failed: {0}")]
    SigningError(String),
}

#[derive(Error, Clone, Debug)]
pub enum VerificationError {
    #[error("Invalid signature type")]
    InvalidSignError,
    #[error("Failed to verify {0} signature: {1}")]
    VerifyError(String, String),
    #[error("Verifying key for {0} can only verify secp256k1 signatures")]
    SignatureError(String),
    #[error("Creating {0} failed")]
    CreationError(String),
    #[error("{0} vk from DER format failed: {1}")]
    IntoRefError(String, String),
    #[error("{0} vk {1} DER format is not implemented")]
    NotImplementedError(String, String),
    #[error("Something went wrong: {0}")]
    GeneralError(String),
}
