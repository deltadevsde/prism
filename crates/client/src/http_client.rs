use async_trait::async_trait;
use prism_api::{
    api::PrismApi,
    types::{AccountRequest, AccountResponse, CommitmentResponse},
};
use prism_common::transaction::{Transaction, TransactionError};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::{Display, Formatter};

pub struct PrismHttpClient {
    client: reqwest::Client,
    base_url: url::Url,
}

impl PrismHttpClient {
    pub fn new(base_url: &str) -> Result<Self, PrismHttpClientError> {
        Ok(Self {
            client: reqwest::Client::new(),
            base_url: reqwest::Url::parse(base_url).map_err(Into::<PrismHttpClientError>::into)?,
        })
    }

    pub async fn fetch<T>(&self, path: &str) -> Result<T, PrismHttpClientError>
    where
        T: DeserializeOwned,
    {
        let url = self.join_url(path)?;
        let response = self.client.get(&url).send().await?;
        response.json::<T>().await.map_err(Into::<PrismHttpClientError>::into)
    }

    pub async fn post<T, U>(&self, path: &str, body: &T) -> Result<U, PrismHttpClientError>
    where
        T: Serialize,
        U: DeserializeOwned,
    {
        let url = self.join_url(path)?;
        let response = self.client.post(&url).json(body).send().await?;
        response.json::<U>().await.map_err(Into::<PrismHttpClientError>::into)
    }

    pub async fn post_no_response<T>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<(), PrismHttpClientError>
    where
        T: Serialize,
    {
        let url = self.join_url(path)?;
        self.client.post(&url).json(body).send().await?;
        Ok(())
    }

    fn join_url(&self, path: &str) -> Result<String, PrismHttpClientError> {
        self.base_url
            .join(path)
            .map(|url| url.to_string())
            .map_err(Into::<PrismHttpClientError>::into)
    }
}

#[async_trait]
impl PrismApi for PrismHttpClient {
    type Error = PrismHttpClientError;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, Self::Error> {
        let req = AccountRequest { id: id.to_string() };
        self.post("/get-account", &req).await
    }

    async fn get_commitment(&self) -> Result<CommitmentResponse, Self::Error> {
        self.fetch("/commitment").await
    }

    async fn post_transaction(&self, tx: &Transaction) -> Result<(), Self::Error> {
        self.post_no_response("/transaction", tx).await
    }
}

#[derive(Debug)]
pub enum PrismHttpClientError {
    Decode,
    Request,
    Status(u16),
    Url(String),
    Unknown,
}

impl Display for PrismHttpClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PrismHttpClientError::Decode => write!(f, "Failed to decode response"),
            PrismHttpClientError::Request => write!(f, "Request failed"),
            PrismHttpClientError::Status(code) => {
                write!(f, "Request failed with status code: {}", code)
            }
            PrismHttpClientError::Url(err) => write!(f, "URL parse error: {}", err),
            PrismHttpClientError::Unknown => write!(f, "Unknown error occurred"),
        }
    }
}

impl From<reqwest::Error> for PrismHttpClientError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_request() {
            PrismHttpClientError::Request
        } else if err.is_decode() {
            PrismHttpClientError::Decode
        } else if err.is_status() {
            PrismHttpClientError::Status(
                err.status().expect("Status error should contain status").into(),
            )
        } else {
            PrismHttpClientError::Unknown
        }
    }
}

impl From<url::ParseError> for PrismHttpClientError {
    fn from(err: url::ParseError) -> Self {
        PrismHttpClientError::Url(err.to_string())
    }
}

impl From<TransactionError> for PrismHttpClientError {
    fn from(_: TransactionError) -> Self {
        PrismHttpClientError::Request
    }
}
