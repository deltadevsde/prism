use anyhow::{Result, anyhow};
use prism_keys::VerifyingKey;
use prism_serde::raw_or_b64;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    api::{PrismApi, noop::NoopPrismApi},
    builder::{ModifyAccountRequestBuilder, RequestBuilder},
    errors::AccountError,
    operation::{Operation, ServiceChallenge},
    transaction::Transaction,
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// A structure representing data signed by an (external) key.
pub struct SignedData {
    /// The key that signed the data
    pub key: VerifyingKey,
    /// The signed data as bytes
    #[schema(
        value_type = String,
        format = Byte,
        example = "jMaZEeHpjIrpO33dkS223jPhurSFixoDJUzNWBAiZKA")]
    #[serde(with = "raw_or_b64")]
    pub data: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default, ToSchema)]
/// Represents an account or service on prism, making up the values of our state
/// tree.
pub struct Account {
    /// The unique identifier for the account.
    id: String,

    /// The transaction nonce for the account.
    nonce: u64,

    /// The current set of valid keys for the account. Any of these keys can be
    /// used to sign transactions.
    valid_keys: Vec<VerifyingKey>,

    /// Arbitrary signed data associated with the account, used for bookkeeping
    /// externally signed data from keys that don't live on Prism.
    signed_data: Vec<SignedData>,

    /// The service challenge for the account, if it is a service.
    service_challenge: Option<ServiceChallenge>,
}

impl Account {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn valid_keys(&self) -> &[VerifyingKey] {
        &self.valid_keys
    }

    pub fn signed_data(&self) -> &[SignedData] {
        &self.signed_data
    }

    pub fn service_challenge(&self) -> Option<&ServiceChallenge> {
        self.service_challenge.as_ref()
    }

    /// Creates a new request builder with the default NoopPrismApi implementation.
    /// This is useful for local testing and validation without a real API connection.
    pub fn builder<'a>() -> RequestBuilder<'a, NoopPrismApi> {
        RequestBuilder::new()
    }

    /// Creates a new request builder using the provided PrismApi implementation.
    /// This allows interaction with a specific API instance.
    pub fn builder_via_api<P>(prism: &P) -> RequestBuilder<'_, P>
    where
        P: PrismApi,
    {
        RequestBuilder::new_with_prism(prism)
    }

    /// Creates a modification request builder for this account using the default NoopPrismApi.
    /// This is useful for local testing and validation without a real API connection.
    pub fn modify(&self) -> ModifyAccountRequestBuilder<NoopPrismApi> {
        RequestBuilder::new().to_modify_account(self)
    }

    /// Creates a modification request builder for this account using the provided PrismApi implementation.
    /// This allows building and submitting transactions that modify the current account state through a specific API.
    pub fn modify_via_api<'a, P>(&self, prism: &'a P) -> ModifyAccountRequestBuilder<'a, P>
    where
        P: PrismApi,
    {
        RequestBuilder::new_with_prism(prism).to_modify_account(self)
    }

    /// Validates and processes an incoming [`Transaction`], updating the account state.
    pub fn process_transaction(&mut self, tx: &Transaction) -> Result<()> {
        self.validate_transaction(tx)?;
        self.process_operation(&tx.operation)?;
        self.nonce += 1;
        Ok(())
    }

    /// Validates a transaction against the current account state. Please note
    /// that the operation must be validated separately.
    fn validate_transaction(&self, tx: &Transaction) -> Result<(), AccountError> {
        if tx.nonce != self.nonce {
            return Err(AccountError::NonceError(tx.nonce, self.nonce));
        }

        match &tx.operation {
            Operation::CreateAccount { id, key, .. }
            | Operation::RegisterService { id, key, .. } => {
                if &tx.id != id {
                    return Err(AccountError::AccountIdError(
                        tx.id.to_string(),
                        id.to_string(),
                    ));
                }
                if &tx.vk != key {
                    return Err(AccountError::AccountKeyError(
                        tx.vk.to_string(),
                        key.to_string(),
                    ));
                }
            }
            _ => {
                if tx.id != self.id {
                    return Err(AccountError::TransactionIdError(
                        tx.id.to_string(),
                        self.id.to_string(),
                    ));
                }
                if !self.valid_keys.contains(&tx.vk) {
                    return Err(AccountError::InvalidKey);
                }
            }
        }

        tx.verify_signature()?;
        Ok(())
    }

    /// Validates an operation against the current account state.
    fn validate_operation(&self, operation: &Operation) -> Result<()> {
        match operation {
            Operation::AddKey { key } => {
                if self.valid_keys.contains(key) {
                    return Err(anyhow!("Key already exists"));
                }
            }
            Operation::RevokeKey { key } => {
                if !self.valid_keys.contains(key) {
                    return Err(anyhow!("Key does not exist"));
                }
            }
            Operation::AddData {
                data,
                data_signature,
            }
            | Operation::SetData {
                data,
                data_signature,
            } => {
                // we only need to do a single signature verification if the
                // user signs transaction and data with their own key
                if !self.valid_keys().contains(&data_signature.verifying_key) {
                    data_signature
                        .verifying_key
                        .verify_signature(data, &data_signature.signature)?;
                }
            }
            Operation::CreateAccount { .. } | Operation::RegisterService { .. } => {
                if !self.is_empty() {
                    return Err(anyhow!("Account already exists"));
                }
            }
        }
        Ok(())
    }

    /// Processes an operation, updating the account state. Should only be run
    /// in the context of a transaction.
    fn process_operation(&mut self, operation: &Operation) -> Result<()> {
        self.validate_operation(operation)?;

        match operation {
            Operation::AddKey { key } => {
                self.valid_keys.push(key.clone());
            }
            Operation::RevokeKey { key } => {
                self.valid_keys.retain(|k| k != key);
            }
            Operation::AddData {
                data,
                data_signature,
            } => {
                self.signed_data.push(SignedData {
                    key: data_signature.verifying_key.clone(),
                    data: data.clone(),
                });
            }
            Operation::SetData {
                data,
                data_signature,
            } => {
                self.signed_data = vec![SignedData {
                    key: data_signature.verifying_key.clone(),
                    data: data.clone(),
                }];
            }
            Operation::CreateAccount { id, key, .. } => {
                self.id = id.clone();
                self.valid_keys.push(key.clone());
            }
            Operation::RegisterService {
                id,
                creation_gate,
                key,
            } => {
                self.id = id.clone();
                self.valid_keys.push(key.clone());
                self.service_challenge = Some(creation_gate.clone());
            }
        }

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.nonce == 0
    }
}
