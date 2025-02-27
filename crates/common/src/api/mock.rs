use async_trait::async_trait;
use mockall::mock;
use std::time::Duration;

use crate::{account::Account, api::PendingTransaction, transaction::Transaction};

use super::{
    types::{AccountResponse, CommitmentResponse},
    PrismApi, PrismApiError, PrismApiTimer,
};

pub struct MockPrismTimer;

impl PrismApiTimer for MockPrismTimer {
    async fn sleep(_: Duration) {}
}

pub struct MockPrismPendingTransaction {
    result: Result<Account, PrismApiError>,
}

impl MockPrismPendingTransaction {
    pub fn with_result(result: Result<Account, PrismApiError>) -> Self {
        Self { result }
    }
}

#[async_trait]
impl PendingTransaction<'_> for MockPrismPendingTransaction {
    type Timer = MockPrismTimer;

    async fn wait_with_interval(&self, _: Duration) -> Result<Account, PrismApiError> {
        self.result.clone()
    }
}

mock! {
    pub PrismApi {
        pub async fn get_account(&self, id: &str) -> Result<AccountResponse, PrismApiError>;
        pub async fn get_commitment(&self) -> Result<CommitmentResponse, PrismApiError>;
        pub async fn post_transaction(&self, transaction: Transaction) -> Result<MockPrismPendingTransaction, PrismApiError>;
    }
}

#[async_trait]
impl PrismApi for MockPrismApi {
    type Timer = MockPrismTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, PrismApiError> {
        MockPrismApi::get_account(self, id).await
    }

    async fn get_commitment(&self) -> Result<CommitmentResponse, PrismApiError> {
        MockPrismApi::get_commitment(self).await
    }

    async fn post_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        MockPrismApi::post_transaction(self, transaction).await
    }
}
