use std::collections::HashMap;

use crate::{
    account::Account,
    digest::Digest,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput, SignatureBundle},
    transaction::{Transaction, UnsignedTransaction},
};
use prism_keys::{CryptoAlgorithm, SigningKey, VerifyingKey};
enum PostCommitAction {
    UpdateStorageOnly,
    RememberServiceKey(String, SigningKey),
    RememberAccountKey(String, SigningKey),
    RemoveAccountKey(String, VerifyingKey),
}

pub struct UncommittedTransaction<'a> {
    transaction: Transaction,
    builder: &'a mut TestTransactionBuilder,
    post_commit_action: PostCommitAction,
}

impl UncommittedTransaction<'_> {
    /// Commits and returns a transaction, updating the builder. Subsequent transactions
    /// built with the same builder will have the correct previous hash.
    pub fn commit(self) -> Transaction {
        let acc = self.builder.accounts.entry(self.transaction.id.clone()).or_default();

        acc.process_transaction(&self.transaction)
            .expect("Adding transaction entry to account should work");

        match self.post_commit_action {
            PostCommitAction::UpdateStorageOnly => (),
            PostCommitAction::RememberAccountKey(id, account_key) => {
                self.builder.account_keys.entry(id).or_default().push(account_key);
            }
            PostCommitAction::RemoveAccountKey(id, key) => {
                if let Some(keys) = self.builder.account_keys.get_mut(&id) {
                    keys.retain(|k| k.verifying_key() != key);
                    if keys.is_empty() {
                        self.builder.account_keys.remove(&id);
                    }
                }
            }
            PostCommitAction::RememberServiceKey(id, service_key) => {
                self.builder.service_keys.insert(id, service_key);
            }
        }

        self.transaction
    }

    /// Returns a transaction without updating the builder.
    /// Can be used to create invalid transactions.
    pub fn build(self) -> Transaction {
        self.transaction
    }
}

pub struct TestTransactionBuilder {
    /// Simulated account storage that is mutated when transactions are applied
    accounts: HashMap<String, Account>,
    /// Remembers private keys of services to simulate account creation via an external service
    service_keys: HashMap<String, SigningKey>,
    /// Remembers private keys of accounts to simulate actions on behalf of these accounts
    account_keys: HashMap<String, Vec<SigningKey>>,
}

impl Default for TestTransactionBuilder {
    fn default() -> Self {
        let accounts = HashMap::new();
        let service_keys = HashMap::new();
        let account_keys = HashMap::new();

        Self {
            accounts,
            service_keys,
            account_keys,
        }
    }
}

impl TestTransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_accounts(&self) -> &HashMap<String, Account> {
        &self.accounts
    }

    pub fn get_service_keys(&self) -> &HashMap<String, SigningKey> {
        &self.service_keys
    }

    pub fn get_account_keys(&self) -> &HashMap<String, Vec<SigningKey>> {
        &self.account_keys
    }

    pub fn get_account(&self, id: &str) -> Option<&Account> {
        self.accounts.get(id)
    }

    pub fn register_service_with_random_keys(
        &mut self,
        algorithm: CryptoAlgorithm,
        id: &str,
    ) -> UncommittedTransaction<'_> {
        let random_service_challenge_key =
            SigningKey::new_with_algorithm(algorithm).expect("Failed to create challenge key");
        let random_service_signing_key =
            SigningKey::new_with_algorithm(algorithm).expect("Failed to create signing key");
        self.register_service(id, random_service_challenge_key, random_service_signing_key)
    }

    pub fn register_service(
        &mut self,
        id: &str,
        challenge_key: SigningKey,
        signing_key: SigningKey,
    ) -> UncommittedTransaction<'_> {
        let vk: VerifyingKey = signing_key.clone().into();
        let op = Operation::RegisterService {
            id: id.to_string(),
            creation_gate: ServiceChallenge::Signed(challenge_key.verifying_key()),
            key: vk.clone(),
        };

        let unsigned_tx = UnsignedTransaction {
            id: id.to_string(),
            operation: op,
            nonce: 0,
        };

        let transaction = unsigned_tx.sign(&signing_key).unwrap();

        UncommittedTransaction {
            transaction,
            builder: self,
            post_commit_action: PostCommitAction::RememberServiceKey(id.to_string(), challenge_key),
        }
    }

    pub fn create_account_with_random_key_signed(
        &mut self,
        algorithm: CryptoAlgorithm,
        id: &str,
        service_id: &str,
    ) -> UncommittedTransaction<'_> {
        let account_signing_key = SigningKey::new_with_algorithm(algorithm)
            .expect("Failed to create account signing key");
        self.create_account_signed(id, service_id, account_signing_key)
    }

    pub fn create_account_signed(
        &mut self,
        id: &str,
        service_id: &str,
        signing_key: SigningKey,
    ) -> UncommittedTransaction<'_> {
        let Some(service_signing_key) = self.service_keys.get(service_id).cloned() else {
            panic!("No existing service found for {}", service_id)
        };

        self.create_account(id, service_id, &service_signing_key, signing_key)
    }

    pub fn create_account_with_random_key(
        &mut self,
        algorithm: CryptoAlgorithm,
        id: &str,
        service_id: &str,
        service_signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let account_signing_key = SigningKey::new_with_algorithm(algorithm)
            .expect("Failed to create account signing key");
        self.create_account(id, service_id, service_signing_key, account_signing_key)
    }

    pub fn create_account(
        &mut self,
        id: &str,
        service_id: &str,
        service_signing_key: &SigningKey,
        signing_key: SigningKey,
    ) -> UncommittedTransaction<'_> {
        // Simulate some external service signing account creation credentials
        let vk = signing_key.verifying_key();
        let hash = Digest::hash_items(&[id.as_bytes(), service_id.as_bytes(), &vk.to_bytes()]);
        let signature = service_signing_key.sign(hash).unwrap();

        let op = Operation::CreateAccount {
            id: id.to_string(),
            service_id: service_id.to_string(),
            challenge: ServiceChallengeInput::Signed(signature.clone()),
            key: vk.clone(),
        };

        let unsigned_tx = UnsignedTransaction {
            id: id.to_string(),
            operation: op,
            nonce: 0,
        };

        let transaction = unsigned_tx.sign(&signing_key).unwrap();

        UncommittedTransaction {
            transaction,
            builder: self,
            post_commit_action: PostCommitAction::RememberAccountKey(id.to_string(), signing_key),
        }
    }

    pub fn add_random_key_verified_with_root(
        &mut self,
        algorithm: CryptoAlgorithm,
        id: &str,
    ) -> UncommittedTransaction<'_> {
        let Some(account_signing_keys) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        let account_signing_key = account_signing_keys.first().unwrap();
        self.add_random_key(algorithm, id, account_signing_key)
    }

    pub fn add_random_key(
        &mut self,
        algorithm: CryptoAlgorithm,
        id: &str,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let random_key =
            SigningKey::new_with_algorithm(algorithm).expect("Failed to create random key").into();
        self.add_key(id, random_key, signing_key)
    }

    pub fn add_key_verified_with_root(
        &mut self,
        id: &str,
        key: VerifyingKey,
    ) -> UncommittedTransaction<'_> {
        let Some(account_signing_keys) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        let account_signing_key = account_signing_keys.first().unwrap();
        self.add_key(id, key, account_signing_key)
    }

    pub fn add_key(
        &mut self,
        id: &str,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let account = self.accounts.get(id).cloned().unwrap_or_default();
        let op = Operation::AddKey { key: key.clone() };

        let unsigned_tx = UnsignedTransaction {
            id: account.id().to_string(),
            operation: op,
            nonce: account.nonce(),
        };

        let transaction = unsigned_tx.sign(signing_key).unwrap();

        UncommittedTransaction {
            transaction,
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }

    pub fn revoke_key_verified_with_root(
        &mut self,
        id: &str,
        key: VerifyingKey,
    ) -> UncommittedTransaction<'_> {
        let Some(account_signing_keys) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        let account_signing_key = account_signing_keys.first().unwrap();
        self.revoke_key(id, key, account_signing_key)
    }

    pub fn revoke_key(
        &mut self,
        id: &str,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let account = self.accounts.get(id).cloned().unwrap_or_default();
        let op = Operation::RevokeKey { key: key.clone() };

        let unsigned_tx = UnsignedTransaction {
            id: account.id().to_string(),
            operation: op,
            nonce: account.nonce(),
        };

        let transaction = unsigned_tx.sign(signing_key).unwrap();

        UncommittedTransaction {
            transaction,
            builder: self,
            post_commit_action: PostCommitAction::RemoveAccountKey(id.to_string(), key),
        }
    }

    pub fn add_randomly_signed_data(
        &mut self,
        algorithm: CryptoAlgorithm,
        id: &str,
        value: Vec<u8>,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let value_signing_key =
            SigningKey::new_with_algorithm(algorithm).expect("Failed to create value signing key");
        self.add_signed_data(id, value, &value_signing_key, signing_key)
    }

    pub fn add_randomly_signed_data_verified_with_root(
        &mut self,
        algorithm: CryptoAlgorithm,
        id: &str,
        value: Vec<u8>,
    ) -> UncommittedTransaction<'_> {
        let value_signing_key =
            SigningKey::new_with_algorithm(algorithm).expect("Failed to create value signing key");
        self.add_signed_data_verified_with_root(id, value, &value_signing_key)
    }

    pub fn add_signed_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signing_key: &SigningKey,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let value_signature_bundle = SignatureBundle {
            verifying_key: value_signing_key.verifying_key(),
            signature: value_signing_key.sign(&value).unwrap(),
        };
        self.add_pre_signed_data(id, value, value_signature_bundle, signing_key)
    }

    pub fn add_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let value_signature_bundle = SignatureBundle {
            verifying_key: value_signing_key.verifying_key(),
            signature: value_signing_key.sign(&value).unwrap(),
        };
        self.add_pre_signed_data_verified_with_root(id, value, value_signature_bundle)
    }

    pub fn add_pre_signed_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: SignatureBundle,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        self.add_data(id, value, value_signature, signing_key)
    }

    pub fn add_pre_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: SignatureBundle,
    ) -> UncommittedTransaction<'_> {
        self.add_data_verified_with_root(id, value, value_signature)
    }

    pub fn add_internally_signed_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let bundle = SignatureBundle {
            verifying_key: signing_key.verifying_key(),
            signature: signing_key.sign(&value).unwrap(),
        };
        self.add_data(id, value, bundle, signing_key)
    }

    pub fn add_internally_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
    ) -> UncommittedTransaction<'_> {
        let Some(account_signing_keys) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        let account_signing_key = account_signing_keys.first().unwrap();
        let bundle = SignatureBundle {
            verifying_key: account_signing_key.verifying_key(),
            signature: account_signing_key.sign(&value).unwrap(),
        };

        self.add_data_verified_with_root(id, value, bundle)
    }

    fn add_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: SignatureBundle,
    ) -> UncommittedTransaction<'_> {
        let Some(account_signing_keys) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        let account_signing_key = account_signing_keys.first().unwrap();
        self.add_data(id, value, value_signature, account_signing_key)
    }

    fn add_data(
        &mut self,
        id: &str,
        data: Vec<u8>,
        data_signature: SignatureBundle,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let account = self.accounts.get(id).cloned().unwrap_or_default();
        let op = Operation::AddData {
            data,
            data_signature,
        };

        let unsigned_tx = UnsignedTransaction {
            id: account.id().to_string(),
            operation: op,
            nonce: account.nonce(),
        };

        let transaction = unsigned_tx.sign(signing_key).unwrap();

        UncommittedTransaction {
            transaction,
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }

    pub fn set_randomly_signed_data(
        &mut self,
        algorithm: CryptoAlgorithm,
        id: &str,
        value: Vec<u8>,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let value_signing_key =
            SigningKey::new_with_algorithm(algorithm).expect("Failed to create value signing key");
        self.set_signed_data(id, value, &value_signing_key, signing_key)
    }

    pub fn set_randomly_signed_data_verified_with_root(
        &mut self,
        algorithm: CryptoAlgorithm,
        id: &str,
        value: Vec<u8>,
    ) -> UncommittedTransaction<'_> {
        let value_signing_key =
            SigningKey::new_with_algorithm(algorithm).expect("Failed to create value signing key");
        self.set_signed_data_verified_with_root(id, value, &value_signing_key)
    }

    pub fn set_internally_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
    ) -> UncommittedTransaction<'_> {
        let Some(account_signing_keys) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        let account_signing_key = account_signing_keys.first().unwrap();
        let bundle = SignatureBundle {
            verifying_key: account_signing_key.verifying_key(),
            signature: account_signing_key.sign(&value).unwrap(),
        };

        self.set_pre_signed_data(id, value, bundle, account_signing_key)
    }

    pub fn set_signed_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signing_key: &SigningKey,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let value_signature_bundle = SignatureBundle {
            verifying_key: value_signing_key.verifying_key(),
            signature: value_signing_key.sign(&value).unwrap(),
        };
        self.set_pre_signed_data(id, value, value_signature_bundle, signing_key)
    }

    pub fn set_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let value_signature_bundle = SignatureBundle {
            verifying_key: value_signing_key.verifying_key(),
            signature: value_signing_key.sign(&value).unwrap(),
        };
        self.set_pre_signed_data_verified_with_root(id, value, value_signature_bundle)
    }

    pub fn set_pre_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: SignatureBundle,
    ) -> UncommittedTransaction<'_> {
        let Some(account_signing_keys) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        let account_signing_key = account_signing_keys.first().unwrap();
        self.set_pre_signed_data(id, value, value_signature, account_signing_key)
    }

    pub fn set_pre_signed_data(
        &mut self,
        id: &str,
        data: Vec<u8>,
        data_signature: SignatureBundle,
        signing_key: &SigningKey,
    ) -> UncommittedTransaction<'_> {
        let account = self.accounts.get(id).cloned().unwrap_or_default();
        let op = Operation::SetData {
            data,
            data_signature,
        };

        let unsigned_tx = UnsignedTransaction {
            id: account.id().to_string(),
            operation: op,
            nonce: account.nonce(),
        };

        let transaction = unsigned_tx.sign(signing_key).unwrap();

        UncommittedTransaction {
            transaction,
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }
}
