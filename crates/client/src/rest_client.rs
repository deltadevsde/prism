use serde::{de::DeserializeOwned, Serialize};
use std::fmt::{Display, Formatter};

pub struct RestClient {
    client: reqwest::Client,
    base_url: url::Url,
}

impl RestClient {
    pub fn new(base_url: &str) -> Result<Self, RestClientError> {
        Ok(Self {
            client: reqwest::Client::new(),
            base_url: reqwest::Url::parse(base_url).map_err(Into::<RestClientError>::into)?,
        })
    }

    pub async fn fetch<T>(&self, path: &str) -> Result<T, RestClientError>
    where
        T: DeserializeOwned,
    {
        let url = self.join_url(path)?;
        let response = self.client.get(&url).send().await?;
        response.json::<T>().await.map_err(Into::<RestClientError>::into)
    }

    pub async fn post<T, U>(&self, path: &str, body: &T) -> Result<U, RestClientError>
    where
        T: Serialize,
        U: DeserializeOwned,
    {
        let url = self.join_url(path)?;
        let response = self.client.post(&url).json(body).send().await?;
        response.json::<U>().await.map_err(Into::<RestClientError>::into)
    }

    pub async fn post_no_response<T>(&self, path: &str, body: &T) -> Result<(), RestClientError>
    where
        T: Serialize,
    {
        let url = self.join_url(path)?;
        self.client.post(&url).json(body).send().await?;
        Ok(())
    }

    fn join_url(&self, path: &str) -> Result<String, RestClientError> {
        self.base_url.join(path).map(|url| url.to_string()).map_err(Into::<RestClientError>::into)
    }
}

#[derive(Debug)]
pub enum RestClientError {
    Decode,
    Request,
    Status(u16),
    Url(String),
    Unknown,
}

impl Display for RestClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RestClientError::Decode => write!(f, "Failed to decode response"),
            RestClientError::Request => write!(f, "Request failed"),
            RestClientError::Status(code) => write!(f, "Request failed with status code: {}", code),
            RestClientError::Url(err) => write!(f, "URL parse error: {}", err),
            RestClientError::Unknown => write!(f, "Unknown error occurred"),
        }
    }
}

impl From<reqwest::Error> for RestClientError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_request() {
            RestClientError::Request
        } else if err.is_decode() {
            RestClientError::Decode
        } else if err.is_status() {
            RestClientError::Status(
                err.status().expect("Status error should contain status").into(),
            )
        } else {
            RestClientError::Unknown
        }
    }
}

impl From<url::ParseError> for RestClientError {
    fn from(err: url::ParseError) -> Self {
        RestClientError::Url(err.to_string())
    }
}
