use anyhow::{Error as AnyhowError, Result};
use prism_errors::{DataAvailabilityError, GeneralError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WasmLightClientError {
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
