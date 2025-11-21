use std::{
    error::Error,
    fmt::{Display, Formatter},
    sync::Arc,
};

use prism_errors::TransactionError;

#[derive(Clone, Debug)]
pub enum PrismApiError {
    /// Error while preparing the transaction
    Transaction(TransactionError),
    /// Error trying to send a request
    RequestFailed(String),
    /// The target of that API request is invalid
    InvalidTarget(String),
    /// Error during (de)serialization of data
    SerdeFailed(String),
    /// Bridge for [`anyhow::Error`]
    Any(Arc<anyhow::Error>),
    /// Unknown error
    Unknown,
}

impl Display for PrismApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transaction(err) => write!(f, "Transaction error {}", err),
            Self::RequestFailed(msg) => write!(f, "Request execution failed: {}", msg),
            Self::InvalidTarget(msg) => write!(f, "Invalid target: {}", msg),
            Self::SerdeFailed(msg) => write!(f, "(De)Serialization error: {}", msg),
            Self::Any(msg) => write!(f, "Unspecific error: {}", msg),
            Self::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl Error for PrismApiError {}

impl From<TransactionError> for PrismApiError {
    fn from(err: TransactionError) -> Self {
        Self::Transaction(err)
    }
}

impl From<anyhow::Error> for PrismApiError {
    fn from(err: anyhow::Error) -> Self {
        Self::Any(Arc::new(err))
    }
}
