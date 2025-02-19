use async_trait::async_trait;
use mockall::mock;
use std::{
    error::Error,
    fmt::{Display, Formatter},
    time::Duration,
};

use crate::{
    account::Account,
    api::PendingTransaction,
    transaction::{Transaction, TransactionError},
};

use super::{
    types::{AccountResponse, CommitmentResponse},
    PrismApi, PrismApiTimer,
};

#[derive(Debug, Clone)]
pub struct MockPrismApiError(String);

impl Display for MockPrismApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mock error: {}", self.0)
    }
}

impl From<TransactionError> for MockPrismApiError {
    fn from(err: TransactionError) -> Self {
        Self(err.to_string())
    }
}

impl Error for MockPrismApiError {}

pub struct MockPrismTimer;

impl PrismApiTimer for MockPrismTimer {
    async fn sleep(_: Duration) {}
}

pub struct MockPrismPendingTransaction {
    result: Result<Account, MockPrismApiError>,
}

impl MockPrismPendingTransaction {
    pub fn with_result(result: Result<Account, MockPrismApiError>) -> Self {
        Self { result }
    }
}

#[async_trait]
impl PendingTransaction for MockPrismPendingTransaction {
    type Error = MockPrismApiError;
    type Timer = MockPrismTimer;

    async fn wait_with_interval(&self, _: Duration) -> Result<Account, Self::Error> {
        self.result.clone()
    }
}

mock! {
    pub PrismApi {
        pub async fn get_account(&self, id: &str) -> Result<AccountResponse, MockPrismApiError>;
        pub async fn get_commitment(&self) -> Result<CommitmentResponse, MockPrismApiError>;
        pub async fn post_transaction(&self, transaction: Transaction) -> Result<MockPrismPendingTransaction, MockPrismApiError>;
    }
}

#[async_trait]
impl PrismApi for MockPrismApi {
    type Error = MockPrismApiError;
    type Timer = MockPrismTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, MockPrismApiError> {
        MockPrismApi::get_account(self, id).await
    }

    async fn get_commitment(&self) -> Result<CommitmentResponse, MockPrismApiError> {
        MockPrismApi::get_commitment(self).await
    }

    async fn post_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<impl PendingTransaction<Error = Self::Error, Timer = Self::Timer>, MockPrismApiError>
    {
        MockPrismApi::post_transaction(self, transaction).await
    }
}
