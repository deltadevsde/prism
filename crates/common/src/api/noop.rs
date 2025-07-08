use async_trait::async_trait;
use std::time::Duration;

use super::{
    PendingTransaction, PrismApi, PrismApiError, PrismApiTimer,
    types::{AccountResponse, CommitmentResponse},
};
use crate::{account::Account, transaction::Transaction};

pub struct NoopTimer;

impl PrismApiTimer for NoopTimer {
    async fn sleep(_: Duration) {}
}

pub struct NoopPendingTransaction;

#[async_trait]
impl PendingTransaction<'_> for NoopPendingTransaction {
    type Timer = NoopTimer;

    async fn wait_with_interval(&self, _: Duration) -> Result<Account, PrismApiError> {
        Err(PrismApiError::Unknown)
    }
}

pub struct NoopPrismApi;

#[async_trait]
impl PrismApi for NoopPrismApi {
    type Timer = NoopTimer;

    async fn get_account(&self, _: &str) -> Result<AccountResponse, PrismApiError> {
        Err(PrismApiError::Unknown)
    }

    async fn get_commitment(&self) -> Result<CommitmentResponse, PrismApiError> {
        Err(PrismApiError::Unknown)
    }

    async fn post_transaction(
        &self,
        _: Transaction,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        Result::<NoopPendingTransaction, PrismApiError>::Err(PrismApiError::Unknown)
    }
}
