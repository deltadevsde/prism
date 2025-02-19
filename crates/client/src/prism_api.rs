use std::{future::Future, time::Duration};

use async_trait::async_trait;
use prism_common::{
    api::{
        types::{AccountRequest, AccountResponse, CommitmentResponse},
        PendingTransaction, PendingTransactionImpl, PrismApi, PrismApiError, PrismApiTimer,
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
    type Timer = PrismHttpTokioTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, PrismApiError> {
        let request = AccountRequest { id: id.to_string() };
        let response = self.post("/get-account", &request).await?;
        Ok(response)
    }

    async fn get_commitment(&self) -> Result<CommitmentResponse, PrismApiError> {
        let response = self.fetch("/commitment").await?;
        Ok(response)
    }

    async fn post_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.post_no_response("/transaction", &transaction).await?;
        Ok(PendingTransactionImpl::new(self, transaction))
    }
}

impl From<PrismHttpClientError> for PrismApiError {
    fn from(err: PrismHttpClientError) -> Self {
        match err {
            PrismHttpClientError::Decode => PrismApiError::SerdeFailed(err.to_string()),
            PrismHttpClientError::Request => PrismApiError::RequestFailed("unspecific".to_string()),
            PrismHttpClientError::Status(status) => {
                PrismApiError::RequestFailed(format!("Status: {}", status))
            }
            PrismHttpClientError::Url(msg) => PrismApiError::InvalidTarget(msg),
            PrismHttpClientError::Unknown => PrismApiError::Unknown,
        }
    }
}
