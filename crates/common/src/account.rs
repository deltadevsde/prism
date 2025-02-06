use anyhow::{anyhow, Result};
use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::raw_or_b64;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
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

    /// Creates a [`Transaction`] that can be used to update or create the
    /// account. The transaction produced could be invalid, and will be
    /// validated before being processed.
    pub fn prepare_transaction(
        &self,
        account_id: String,
        operation: Operation,
        sk: &SigningKey,
    ) -> Result<Transaction> {
        let vk = sk.verifying_key();

        let mut tx = Transaction {
            id: account_id,
            nonce: self.nonce,
            operation,
            signature: Signature::Placeholder,
            vk,
        };

        tx.sign(sk)?;

        Ok(tx)
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
    fn validate_transaction(&self, tx: &Transaction) -> Result<()> {
        if tx.nonce != self.nonce {
            return Err(anyhow!(
                "Nonce does not match. {} != {}",
                tx.nonce,
                self.nonce
            ));
        }

        match tx.operation {
            Operation::CreateAccount { .. } | Operation::RegisterService { .. } => {}
            _ => {
                if tx.id != self.id {
                    return Err(anyhow!("Transaction ID does not match account ID"));
                }
                if !self.valid_keys.contains(&tx.vk) {
                    return Err(anyhow!("Invalid key"));
                }
            }
        }

        let msg = tx.get_signature_payload()?;
        tx.vk.verify_signature(&msg, &tx.signature)?;

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
