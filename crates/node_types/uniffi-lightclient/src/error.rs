use thiserror::Error;

/// Result type alias for LightClient operations that can fail with a LightClientError
pub type Result<T, E = LightClientError> = std::result::Result<T, E>;

/// Represents all possible errors that can occur in the LightClient.
#[derive(Error, Debug, uniffi::Error)]
pub enum LightClientError {
    /// Error returned when network operations fail
    #[error("Network error: {msg}")]
    Network {
        /// Description of the network error
        msg: String,
    },

    /// Error returned when initialization operations fail
    #[error("Initialization error: {msg}")]
    Initialization {
        /// Description of the initialization error
        msg: String,
    },

    /// Error returned when verification operations fail
    #[error("Verification error: {msg}")]
    Verification {
        /// Description of the verification error
        msg: String,
    },

    /// Error returned when event handling operations fail
    #[error("Event error: {msg}")]
    Event {
        /// Description of the event error
        msg: String,
    },

    /// General error for all other cases
    #[error("General error: {msg}")]
    General {
        /// Description of the general error
        msg: String,
    },
}

impl LightClientError {
    pub fn network_error(msg: impl Into<String>) -> Self {
        Self::Network { msg: msg.into() }
    }

    pub fn initialization_error(msg: impl Into<String>) -> Self {
        Self::Initialization { msg: msg.into() }
    }

    pub fn verification_error(msg: impl Into<String>) -> Self {
        Self::Verification { msg: msg.into() }
    }

    pub fn event_error(msg: impl Into<String>) -> Self {
        Self::Event { msg: msg.into() }
    }

    pub fn general_error(msg: impl Into<String>) -> Self {
        Self::General { msg: msg.into() }
    }
}
