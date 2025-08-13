use anyhow::{Error as AnyhowError, Result};
use prism_errors::{DataAvailabilityError, GeneralError};
use thiserror::Error;

use crate::config::WasmLightClientConfigError;

// TODO: use the error types and improve them (use prism errors)

#[derive(Error, Debug)]
pub enum WasmLightClientError {
    #[error(transparent)]
    Config(#[from] WasmLightClientConfigError),
    #[error(transparent)]
    Worker(#[from] WorkerError),
    #[error(transparent)]
    DataAvailability(#[from] DataAvailabilityError),
    #[error(transparent)]
    General(#[from] GeneralError),
    #[error(transparent)]
    Other(#[from] AnyhowError),
}

#[derive(Error, Debug)]
pub enum WorkerError {
    #[error("worker communication failed: {0}")]
    CommunicationError(String),
    #[error("worker initialization failed: {0}")]
    InitializationError(String),
    #[error("message channel closed")]
    ChannelClosed,
}

pub type WasmResult<T> = Result<T, WasmLightClientError>;
