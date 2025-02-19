use std::{future::Future, time::Duration};

use async_trait::async_trait;
use prism_common::{
    api::{
        types::{AccountRequest, AccountResponse, CommitmentResponse},
        PendingTransaction, PendingTransactionImpl, PrismApi, PrismApiTimer,
    },
    transaction::Transaction,
};

use crate::{PrismHttpClient, PrismHttpClientError};

pub struct PrismHttpTokioTimer;

impl PrismApiTimer for PrismHttpTokioTimer {
    fn sleep(duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }
}

#[async_trait]
impl PrismApi for PrismHttpClient {
    type Error = PrismHttpClientError;
    type Timer = PrismHttpTokioTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, Self::Error> {
        let req = AccountRequest { id: id.to_string() };
        self.post("/get-account", &req).await
    }

    async fn get_commitment(&self) -> Result<CommitmentResponse, Self::Error> {
        self.fetch("/commitment").await
    }

    async fn post_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<impl PendingTransaction<Error = Self::Error, Timer = Self::Timer>, Self::Error>
    {
        self.post_no_response("/transaction", &transaction).await?;
        Ok(PendingTransactionImpl::new(self, transaction))
    }
}
