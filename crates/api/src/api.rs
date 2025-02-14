use std::time::Duration;

use prism_common::{
    account::Account,
    operation::SignatureBundle,
    transaction::{Transaction, TransactionError},
};
use prism_keys::{SigningKey, VerifyingKey};
use tokio::time::sleep;

use crate::{
    builder::RequestBuilder,
    types::{AccountResponse, CommitmentResponse},
};

pub trait PrismApi
where
    Self: Sized + Send + Sync,
{
    type Error: From<TransactionError>;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, Self::Error>;

    async fn get_commitment(&self) -> Result<CommitmentResponse, Self::Error>;

    fn build_request(&self) -> RequestBuilder<Self> {
        RequestBuilder::new(self)
    }

    async fn post_transaction(&self, tx: &Transaction) -> Result<(), Self::Error>;

    async fn register_service(
        &self,
        id: String,
        challenge_key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<PendingTransaction<Self>, Self::Error> {
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
    ) -> Result<PendingTransaction<Self>, Self::Error> {
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
    ) -> Result<PendingTransaction<Self>, Self::Error> {
        self.build_request()
            .modify_existing()
            .for_account(account)
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
    ) -> Result<PendingTransaction<Self>, Self::Error> {
        self.build_request()
            .modify_existing()
            .for_account(account)
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
    ) -> Result<PendingTransaction<Self>, Self::Error> {
        self.build_request()
            .modify_existing()
            .for_account(account)
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
    ) -> Result<PendingTransaction<Self>, Self::Error> {
        self.build_request()
            .modify_existing()
            .for_account(account)
            .set_data(data, data_signature)?
            .sign(signing_key)?
            .send()
            .await
    }
}

pub struct PendingTransaction<'a, P>
where
    P: PrismApi,
{
    prism: &'a P,
    transaction: Transaction,
}

impl<'a, P> PendingTransaction<'a, P>
where
    P: PrismApi,
{
    const DEFAULT_POLLING_INTERVAL: Duration = Duration::from_secs(5);

    pub fn new(prism: &'a P, transaction: Transaction) -> Self {
        Self { prism, transaction }
    }

    pub async fn wait(&self) -> Result<(), P::Error> {
        self.wait_with_interval(Self::DEFAULT_POLLING_INTERVAL).await
    }

    pub async fn wait_with_interval(&self, interval: Duration) -> Result<(), P::Error> {
        loop {
            if let AccountResponse {
                account: Some(account),
                proof: _,
            } = self.prism.get_account(&self.transaction.id).await?
            {
                if account.nonce() > self.transaction.nonce {
                    return Ok(());
                }
            };
            sleep(interval).await;
        }
    }
}
