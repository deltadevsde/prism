#[cfg(feature = "mockall")]
pub mod mock;
pub mod noop;
pub mod types;

use async_trait::async_trait;
use prism_keys::{SigningKey, VerifyingKey};
use std::{
    error::Error,
    fmt::{Debug, Display},
    future::Future,
    time::Duration,
};

use crate::{
    account::Account,
    builder::RequestBuilder,
    operation::SignatureBundle,
    transaction::{Transaction, TransactionError},
};
use types::{AccountResponse, CommitmentResponse};

#[async_trait]
pub trait PrismApi
where
    Self: Sized + Send + Sync,
{
    type Error: From<TransactionError> + Error + Debug + Display + Send + Sync + 'static;
    type Timer: PrismApiTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, Self::Error>;

    async fn get_commitment(&self) -> Result<CommitmentResponse, Self::Error>;

    async fn post_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<impl PendingTransaction<Error = Self::Error, Timer = Self::Timer>, Self::Error>;

    fn build_request(&self) -> RequestBuilder<Self> {
        RequestBuilder::new_with_prism(self)
    }

    async fn register_service(
        &self,
        id: String,
        challenge_key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Error = Self::Error, Timer = Self::Timer>, Self::Error>
    {
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
    ) -> Result<impl PendingTransaction<Error = Self::Error, Timer = Self::Timer>, Self::Error>
    {
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
    ) -> Result<impl PendingTransaction<Error = Self::Error, Timer = Self::Timer>, Self::Error>
    {
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
    ) -> Result<impl PendingTransaction<Error = Self::Error, Timer = Self::Timer>, Self::Error>
    {
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
    ) -> Result<impl PendingTransaction<Error = Self::Error, Timer = Self::Timer>, Self::Error>
    {
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
    ) -> Result<impl PendingTransaction<Error = Self::Error, Timer = Self::Timer>, Self::Error>
    {
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
pub trait PendingTransaction
where
    Self: Send + Sync,
{
    type Error: From<TransactionError> + Error + Debug + Display + Send + Sync + 'static;
    type Timer: PrismApiTimer;

    async fn wait(&self) -> Result<Account, Self::Error> {
        self.wait_with_interval(DEFAULT_POLLING_INTERVAL).await
    }

    async fn wait_with_interval(&self, interval: Duration) -> Result<Account, Self::Error>;
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
impl<P> PendingTransaction for PendingTransactionImpl<'_, P>
where
    P: PrismApi,
{
    type Error = P::Error;
    type Timer = P::Timer;

    async fn wait_with_interval(&self, interval: Duration) -> Result<Account, Self::Error> {
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
