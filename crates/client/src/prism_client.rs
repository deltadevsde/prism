use prism_api::{AccountRequest, AccountResponse};
use prism_common::{
    account::Account,
    digest::Digest,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput, SignatureBundle},
};
use prism_keys::{SigningKey, VerifyingKey};

use crate::rest_client::{RestClient, RestClientError};

struct PrismClient {
    rest_client: RestClient,
}

impl PrismClient {
    pub fn new(url: &str) -> Result<Self, RestClientError> {
        Ok(PrismClient {
            rest_client: RestClient::new(url)?,
        })
    }

    pub async fn register_service(
        &self,
        id: String,
        challenge_key: SigningKey,
        signing_key: &SigningKey,
    ) -> Result<(), PrismClientError> {
        let vk: VerifyingKey = signing_key.clone().into();
        let op = Operation::RegisterService {
            id: id.clone(),
            creation_gate: ServiceChallenge::Signed(challenge_key.verifying_key()),
            key: vk.clone(),
        };

        let tx = Account::default()
            .prepare_transaction(id, op, &signing_key)
            .map_err(Into::<PrismClientError>::into)?;
        self.rest_client.post("/transaction", &tx).await.map_err(Into::<PrismClientError>::into)
    }

    pub async fn create_account(
        &self,
        id: String,
        service_id: String,
        service_signing_key: &SigningKey,
        signing_key: &SigningKey,
    ) -> Result<(), PrismClientError> {
        let vk = signing_key.verifying_key();
        let hash = Digest::hash_items(&[id.as_bytes(), service_id.as_bytes(), &vk.to_bytes()]);
        let signature = service_signing_key.sign(&hash.to_bytes());

        let op = Operation::CreateAccount {
            id: id.clone(),
            service_id,
            challenge: ServiceChallengeInput::Signed(signature.clone()),
            key: vk.clone(),
        };

        let tx = Account::default()
            .prepare_transaction(id, op, signing_key)
            .map_err(Into::<PrismClientError>::into)?;
        self.rest_client.post("/transaction", &tx).await.map_err(Into::<PrismClientError>::into)
    }

    pub async fn add_key(
        &mut self,
        account: &Account,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<(), PrismClientError> {
        let op = Operation::AddKey { key };

        let tx = account
            .prepare_transaction(account.id().to_string(), op, signing_key)
            .map_err(Into::<PrismClientError>::into)?;
        self.rest_client.post("/transaction", &tx).await.map_err(Into::<PrismClientError>::into)
    }

    pub async fn revoke_key(
        &mut self,
        account: &Account,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<(), PrismClientError> {
        let op = Operation::RevokeKey { key };

        let tx = account
            .prepare_transaction(account.id().to_string(), op, signing_key)
            .map_err(Into::<PrismClientError>::into)?;
        self.rest_client.post("/transaction", &tx).await.map_err(Into::<PrismClientError>::into)
    }

    pub async fn add_data(
        &self,
        account: &Account,
        data: Vec<u8>,
        data_signature: SignatureBundle,
        signing_key: &SigningKey,
    ) -> Result<(), PrismClientError> {
        let op = Operation::AddData {
            data,
            data_signature,
        };

        let tx = account
            .prepare_transaction(account.id().to_string(), op, signing_key)
            .map_err(Into::<PrismClientError>::into)?;
        self.rest_client.post("/transaction", &tx).await.map_err(Into::<PrismClientError>::into)
    }

    pub async fn set_data(
        &self,
        account: &Account,
        data: Vec<u8>,
        data_signature: SignatureBundle,
        signing_key: &SigningKey,
    ) -> Result<(), PrismClientError> {
        let op = Operation::SetData {
            data,
            data_signature,
        };

        let tx = account
            .prepare_transaction(account.id().to_string(), op, signing_key)
            .map_err(Into::<PrismClientError>::into)?;
        self.rest_client.post("/transaction", &tx).await.map_err(Into::<PrismClientError>::into)
    }

    pub async fn get_account(&self, id: String) -> Result<AccountResponse, PrismClientError> {
        let req = AccountRequest { id };
        self.rest_client.post("/get-account", &req).await.map_err(Into::<PrismClientError>::into)
    }
}

#[derive(Debug)]
pub enum PrismClientError {
    Sending(String),
    Transaction(String),
}

impl std::fmt::Display for PrismClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PrismClientError::Sending(msg) => write!(f, "Error sending request: {}", msg),
            PrismClientError::Transaction(msg) => write!(f, "Transaction error: {}", msg),
        }
    }
}

impl From<RestClientError> for PrismClientError {
    fn from(error: RestClientError) -> Self {
        PrismClientError::Sending(error.to_string())
    }
}

impl From<anyhow::Error> for PrismClientError {
    fn from(error: anyhow::Error) -> Self {
        PrismClientError::Transaction(error.to_string())
    }
}
