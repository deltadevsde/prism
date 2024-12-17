use anyhow::{anyhow, Result};
use prism_keys::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    operation::{Operation, ServiceChallenge},
    transaction::Transaction,
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Hash, Default)]
pub struct Account {
    pub id: String,
    pub nonce: u64,
    pub valid_keys: Vec<VerifyingKey>,
    pub signed_data: Vec<(VerifyingKey, Vec<u8>)>,

    ///  Only set when the account is a service
    pub service_challenge: Option<ServiceChallenge>,
}

impl Account {
    pub fn prepare_transaction(
        &self,
        account_id: String,
        operation: Operation,
        sk: &SigningKey,
    ) -> Result<Transaction> {
        let vk = sk.verifying_key();
        match &operation {
            Operation::CreateAccount { id, .. } | Operation::RegisterService { id, .. } => {
                if *id != account_id {
                    return Err(anyhow!("Operation ID does not match account ID"));
                }
            }
            _ => {
                if !self.valid_keys.contains(&vk) {
                    return Err(anyhow!("Invalid key"));
                }
            }
        }

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

    pub fn process_transaction(&mut self, tx: &Transaction) -> Result<()> {
        self.validate_transaction(tx)?;
        self.process_operation(&tx.operation)?;
        self.nonce += 1;
        Ok(())
    }

    pub fn validate_transaction(&self, tx: &Transaction) -> Result<()> {
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

        self.validate_operation(&tx.operation)?;

        Ok(())
    }

    pub fn validate_operation(&self, operation: &Operation) -> Result<()> {
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
            } => {
                // if the data is externally signed
                data_signature.verifying_key.verify_signature(data, &data_signature.signature)?;
            }
            Operation::CreateAccount { .. } | Operation::RegisterService { .. } => {
                if !self.is_empty() {
                    return Err(anyhow!("Account already exists"));
                }
            }
        }
        Ok(())
    }

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
                self.signed_data.push((data_signature.verifying_key.clone(), data.clone()));
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
