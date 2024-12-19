use std::collections::HashMap;

use crate::{
    digest::Digest,
    hashchain::{Hashchain, HashchainEntry},
    operation::{ServiceChallenge, ServiceChallengeInput, SignatureBundle},
    transaction::Transaction,
};
use prism_keys::{SigningKey, VerifyingKey};
enum PostCommitAction {
    UpdateStorageOnly,
    RememberServiceKey(String, SigningKey),
    RememberAccountKey(String, SigningKey),
}

pub struct UncommittedTransaction<'a> {
    transaction: Transaction,
    builder: &'a mut TransactionBuilder,
    post_commit_action: PostCommitAction,
}

impl UncommittedTransaction<'_> {
    /// Commits and returns a transaction, updating the builder. Subsequent transactions
    /// built with the same builder will have the correct previous hash.
    pub fn commit(self) -> Transaction {
        let hc = self
            .builder
            .hashchains
            .entry(self.transaction.id.clone())
            .or_insert_with(Hashchain::empty);

        hc.add_entry(self.transaction.entry.clone())
            .expect("Adding transaction entry to hashchain should work");

        match self.post_commit_action {
            PostCommitAction::UpdateStorageOnly => (),
            PostCommitAction::RememberAccountKey(id, account_key) => {
                self.builder.account_keys.insert(id, account_key);
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

pub struct TransactionBuilder {
    /// Simulated hashchain storage that is mutated when transactions are applied
    hashchains: HashMap<String, Hashchain>,
    /// Remembers private keys of services to simulate account creation via an external service
    service_keys: HashMap<String, SigningKey>,
    /// Remembers private keys of accounts to simulate actions on behalf of these accounts
    account_keys: HashMap<String, SigningKey>,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        let hashchains = HashMap::new();
        let service_keys = HashMap::new();
        let account_keys = HashMap::new();

        Self {
            hashchains,
            service_keys,
            account_keys,
        }
    }
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_hashchain(&self, id: &str) -> Option<&Hashchain> {
        self.hashchains.get(id)
    }

    pub fn register_service_with_random_keys(
        &mut self,
        algorithm: &str,
        id: &str,
    ) -> UncommittedTransaction {
        let random_service_challenge_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create challenge key");
        let random_service_signing_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create signing key");
        self.register_service(id, random_service_challenge_key, random_service_signing_key)
    }

    pub fn register_service(
        &mut self,
        id: &str,
        challenge_key: SigningKey,
        signing_key: SigningKey,
    ) -> UncommittedTransaction {
        let vk: VerifyingKey = signing_key.clone().into();
        let entry = HashchainEntry::new_register_service(
            id.to_string(),
            ServiceChallenge::from(challenge_key.clone()),
            vk,
            &signing_key,
        );

        UncommittedTransaction {
            transaction: Transaction {
                id: id.to_string(),
                entry,
            },
            builder: self,
            post_commit_action: PostCommitAction::RememberServiceKey(id.to_string(), challenge_key),
        }
    }

    pub fn create_account_with_random_key_signed(
        &mut self,
        algorithm: &str,
        id: &str,
        service_id: &str,
    ) -> UncommittedTransaction {
        let account_signing_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create account signing key");
        self.create_account_signed(id, service_id, account_signing_key)
    }

    pub fn create_account_signed(
        &mut self,
        id: &str,
        service_id: &str,
        signing_key: SigningKey,
    ) -> UncommittedTransaction {
        let Some(service_signing_key) = self.service_keys.get(service_id).cloned() else {
            panic!("No existing service found for {}", service_id)
        };

        self.create_account(id, service_id, &service_signing_key, signing_key)
    }

    pub fn create_account_with_random_key(
        &mut self,
        algorithm: &str,
        id: &str,
        service_id: &str,
        service_signing_key: &SigningKey,
    ) -> UncommittedTransaction {
        let account_signing_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create account signing key");
        self.create_account(id, service_id, service_signing_key, account_signing_key)
    }

    pub fn create_account(
        &mut self,
        id: &str,
        service_id: &str,
        service_signing_key: &SigningKey,
        signing_key: SigningKey,
    ) -> UncommittedTransaction {
        // Simulate some external service signing account creation credentials
        let vk = signing_key.verifying_key();
        let hash = Digest::hash_items(&[id.as_bytes(), service_id.as_bytes(), &vk.to_bytes()]);
        let signature = service_signing_key.sign(&hash.to_bytes());

        let entry = HashchainEntry::new_create_account(
            id.to_string(),
            service_id.to_string(),
            ServiceChallengeInput::Signed(signature),
            vk.clone(),
            &signing_key,
        );

        UncommittedTransaction {
            transaction: Transaction {
                id: id.to_string(),
                entry,
            },
            builder: self,
            post_commit_action: PostCommitAction::RememberAccountKey(id.to_string(), signing_key),
        }
    }

    pub fn add_random_key_verified_with_root(&mut self, algorithm: &str, id: &str) -> UncommittedTransaction {
        let Some(account_signing_key) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        self.add_random_key(algorithm, id, &account_signing_key, 0)
    }

    pub fn add_random_key(
        &mut self,
        algorithm: &str,
        id: &str,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedTransaction {
        let random_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create random key").into();
        self.add_key(id, random_key, signing_key, key_idx)
    }

    pub fn add_key_verified_with_root(
        &mut self,
        id: &str,
        key: VerifyingKey,
    ) -> UncommittedTransaction {
        let Some(account_signing_key) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        self.add_key(id, key, &account_signing_key, 0)
    }

    pub fn add_key(
        &mut self,
        id: &str,
        key: VerifyingKey,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedTransaction {
        let last_hash = self.hashchains.get(id).map_or(Digest::zero(), Hashchain::last_hash);

        let entry = HashchainEntry::new_add_key(key, last_hash, signing_key, key_idx);

        UncommittedTransaction {
            transaction: Transaction {
                id: id.to_string(),
                entry,
            },
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }

    pub fn revoke_key_verified_with_root(
        &mut self,
        id: &str,
        key: VerifyingKey,
    ) -> UncommittedTransaction {
        let Some(account_signing_key) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        self.revoke_key(id, key, &account_signing_key, 0)
    }

    pub fn revoke_key(
        &mut self,
        id: &str,
        key: VerifyingKey,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedTransaction {
        let last_hash = self.hashchains.get(id).map_or(Digest::zero(), Hashchain::last_hash);

        let entry = HashchainEntry::new_revoke_key(key, last_hash, signing_key, key_idx);

        UncommittedTransaction {
            transaction: Transaction {
                id: id.to_string(),
                entry,
            },
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }

    pub fn add_randomly_signed_data(
        &mut self,
        algorithm: &str,
        id: &str,
        value: Vec<u8>,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedTransaction {
        let value_signing_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create value signing key");
        self.add_signed_data(id, value, &value_signing_key, signing_key, key_idx)
    }

    pub fn add_randomly_signed_data_verified_with_root(
        &mut self,
        algorithm: &str,
        id: &str,
        value: Vec<u8>,
    ) -> UncommittedTransaction {
        let value_signing_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create value signing key");
        self.add_signed_data_verified_with_root(id, value, &value_signing_key)
    }

    pub fn add_signed_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signing_key: &SigningKey,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedTransaction {
        let value_signature_bundle = SignatureBundle {
            verifying_key: value_signing_key.verifying_key(),
            signature: value_signing_key.sign(&value),
        };
        self.add_pre_signed_data(id, value, value_signature_bundle, signing_key, key_idx)
    }

    pub fn add_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signing_key: &SigningKey,
    ) -> UncommittedTransaction {
        let value_signature_bundle = SignatureBundle {
            verifying_key: value_signing_key.verifying_key(),
            signature: value_signing_key.sign(&value),
        };
        self.add_pre_signed_data_verified_with_root(id, value, value_signature_bundle)
    }

    pub fn add_pre_signed_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: SignatureBundle,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedTransaction {
        self.add_data(id, value, Some(value_signature), signing_key, key_idx)
    }

    pub fn add_pre_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: SignatureBundle,
    ) -> UncommittedTransaction {
        self.add_data_verified_with_root(id, value, Some(value_signature))
    }

    pub fn add_unsigned_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedTransaction {
        self.add_data(id, value, None, signing_key, key_idx)
    }

    pub fn add_unsigned_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
    ) -> UncommittedTransaction {
        self.add_data_verified_with_root(id, value, None)
    }

    fn add_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: Option<SignatureBundle>,
    ) -> UncommittedTransaction {
        let Some(account_signing_key) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        self.add_data(id, value, value_signature, &account_signing_key, 0)
    }

    fn add_data(
        &mut self,
        id: &str,
        data: Vec<u8>,
        data_signature: Option<SignatureBundle>,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedTransaction {
        let last_hash = self.hashchains.get(id).map_or(Digest::zero(), Hashchain::last_hash);

        let entry =
            HashchainEntry::new_add_data(data, data_signature, last_hash, signing_key, key_idx);

        UncommittedTransaction {
            transaction: Transaction {
                id: id.to_string(),
                entry,
            },
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }
}
