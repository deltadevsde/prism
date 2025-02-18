use std::{
    error::Error,
    fmt::{Display, Formatter},
    time::Duration,
};

use async_trait::async_trait;

use super::{
    types::{AccountResponse, CommitmentResponse},
    PrismApi, PrismApiTimer,
};
use crate::transaction::{Transaction, TransactionError};

pub struct NoopPrismApi {}

#[derive(Debug)]
pub struct NoopPrismError;

impl Display for NoopPrismError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoopPrismError")
    }
}

impl Error for NoopPrismError {}

impl From<TransactionError> for NoopPrismError {
    fn from(_: TransactionError) -> Self {
        NoopPrismError
    }
}

pub struct NoopTimer;

impl PrismApiTimer for NoopTimer {
    async fn sleep(_: Duration) {}
}

#[async_trait]
impl PrismApi for NoopPrismApi {
    type Error = NoopPrismError;
    type Timer = NoopTimer;

    async fn get_account(&self, _: &str) -> Result<AccountResponse, Self::Error> {
        Err(NoopPrismError)
    }

    async fn get_commitment(&self) -> Result<CommitmentResponse, Self::Error> {
        Err(NoopPrismError)
    }

    async fn post_transaction(&self, _: &Transaction) -> Result<(), Self::Error> {
        Err(NoopPrismError)
    }
}
