#[cfg(feature = "mockall")]
pub mod mock;
pub mod noop;
pub mod types;

use async_trait::async_trait;
use prism_errors::TransactionError;
use prism_keys::{SigningKey, VerifyingKey};
use std::{
    error::Error,
    fmt::{Debug, Display, Formatter},
    future::Future,
    sync::Arc,
    time::Duration,
};

use crate::{
    account::Account, builder::RequestBuilder, operation::SignatureBundle, transaction::Transaction,
};
use types::{AccountResponse, CommitmentResponse};

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
        PrismApiError::Transaction(err)
    }
}

impl From<anyhow::Error> for PrismApiError {
    fn from(err: anyhow::Error) -> Self {
        PrismApiError::Any(Arc::new(err))
    }
}

#[async_trait]
pub trait PrismApi
where
    Self: Sized + Send + Sync,
{
    type Timer: PrismApiTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, PrismApiError>;

    async fn get_commitment(&self) -> Result<CommitmentResponse, PrismApiError>;

    async fn post_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError>;

    fn build_request(&self) -> RequestBuilder<Self> {
        RequestBuilder::new_with_prism(self)
    }

    async fn register_service(
        &self,
        id: String,
        challenge_key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.build_request()
            .register_service()
            .with_id(id)
            .with_key(signing_key.verifying_key())
            .requiring_signed_challenge(challenge_key)?
            .sign(signing_key)?
            .send()
            .await
    }

    async fn create_account(
        &self,
        id: String,
        service_id: String,
        service_signing_key: &SigningKey,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.build_request()
            .create_account()
            .with_id(id)
            .for_service_with_id(service_id)
            .with_key(signing_key.verifying_key())
            .meeting_signed_challenge(service_signing_key)?
            .sign(signing_key)?
            .send()
            .await
    }

    async fn add_key(
        &self,
        account: &Account,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.build_request()
            .to_modify_account(account)
            .add_key(key)?
            .sign(signing_key)?
            .send()
            .await
    }

    async fn revoke_key(
        &self,
        account: &Account,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.build_request()
            .to_modify_account(account)
            .revoke_key(key)?
            .sign(signing_key)?
            .send()
            .await
    }

    async fn add_data(
        &self,
        account: &Account,
        data: Vec<u8>,
        data_signature: SignatureBundle,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.build_request()
            .to_modify_account(account)
            .add_data(data, data_signature)?
            .sign(signing_key)?
            .send()
            .await
    }

    async fn set_data(
        &self,
        account: &Account,
        data: Vec<u8>,
        data_signature: SignatureBundle,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.build_request()
            .to_modify_account(account)
            .set_data(data, data_signature)?
            .sign(signing_key)?
            .send()
            .await
    }
}

pub trait PrismApiTimer {
    fn sleep(duration: Duration) -> impl Future<Output = ()> + Send;
}

const DEFAULT_POLLING_INTERVAL: Duration = Duration::from_secs(5);

#[async_trait]
pub trait PendingTransaction<'a>
where
    Self: Send + Sync,
{
    type Timer: PrismApiTimer;

    async fn wait(&self) -> Result<Account, PrismApiError> {
        self.wait_with_interval(DEFAULT_POLLING_INTERVAL).await
    }

    async fn wait_with_interval(&self, interval: Duration) -> Result<Account, PrismApiError>;
}

pub struct PendingTransactionImpl<'a, P>
where
    P: PrismApi,
{
    prism: &'a P,
    transaction: Transaction,
}

impl<'a, P> PendingTransactionImpl<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: &'a P, transaction: Transaction) -> Self {
        Self { prism, transaction }
    }
}

#[async_trait]
impl<'a, P> PendingTransaction<'a> for PendingTransactionImpl<'a, P>
where
    P: PrismApi,
{
    type Timer = P::Timer;

    async fn wait_with_interval(&self, interval: Duration) -> Result<Account, PrismApiError> {
        loop {
            if let AccountResponse {
                account: Some(account),
                proof: _,
            } = self.prism.get_account(&self.transaction.id).await?
            {
                if account.nonce() > self.transaction.nonce {
                    return Ok(account);
                }
            };
            Self::Timer::sleep(interval).await;
        }
    }
}
