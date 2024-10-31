use std::{collections::HashMap, sync::Arc};

use jmt::{mock::MockTreeStore, KeyHash};

use crate::{
    digest::Digest,
    hasher::Hasher,
    keys::{SigningKey, VerifyingKey},
    operation::{Operation, SignatureBundle},
    test_utils::create_mock_signing_key,
    tree::{HashchainResponse::*, KeyDirectoryTree, SnarkableTree},
};

enum PostCommitAction {
    UpdateStorageOnly,
    RememberServiceKey(String, SigningKey),
    RememberAccountKey(String, SigningKey),
}

pub struct UncommittedOperation<'a> {
    operation: Operation,
    builder: &'a mut OpsBuilder,
    post_commit_action: PostCommitAction,
}

impl UncommittedOperation<'_> {
    pub fn ex(self) -> Operation {
        self.builder
            .tree
            .process_operation(&self.operation)
            .expect("Processing operation should work");

        match self.post_commit_action {
            PostCommitAction::UpdateStorageOnly => (),
            PostCommitAction::RememberAccountKey(id, account_key) => {
                self.builder.account_keys.insert(id, account_key);
            }
            PostCommitAction::RememberServiceKey(id, service_key) => {
                self.builder.service_keys.insert(id, service_key);
            }
        }

        self.operation
    }

    pub fn op(self) -> Operation {
        self.operation
    }
}

pub struct OpsBuilder {
    /// Simulated hashchain storage that is mutated when operations are applied
    tree: Box<dyn SnarkableTree>,
    /// Remembers private keys of services to simulate account creation via an external service
    service_keys: HashMap<String, SigningKey>,
    /// Remembers private keys of accounts to simulate actions on behalf of these accounts
    account_keys: HashMap<String, SigningKey>,
}

impl Default for OpsBuilder {
    fn default() -> Self {
        let store = Arc::new(MockTreeStore::default());
        let tree = Box::new(KeyDirectoryTree::new(store));
        let service_keys = HashMap::new();
        let account_keys = HashMap::new();

        Self {
            tree,
            service_keys,
            account_keys,
        }
    }
}

impl OpsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_service_with_random_key(&mut self, id: &str) -> UncommittedOperation {
        let random_service_key = create_mock_signing_key();
        self.register_service(id, random_service_key)
    }

    pub fn register_service(
        &mut self,
        id: &str,
        service_signing_key: SigningKey,
    ) -> UncommittedOperation {
        let op =
            Operation::new_register_service(id.to_string(), service_signing_key.clone().into());

        UncommittedOperation {
            operation: op,
            builder: self,
            post_commit_action: PostCommitAction::RememberServiceKey(
                id.to_string(),
                service_signing_key,
            ),
        }
    }

    pub fn create_account_with_random_key(
        &mut self,
        id: &str,
        service_id: &str,
    ) -> UncommittedOperation {
        let random_signing_key = create_mock_signing_key();
        self.create_account(id, service_id, random_signing_key)
    }

    pub fn create_account(
        &mut self,
        id: &str,
        service_id: &str,
        signing_key: SigningKey,
    ) -> UncommittedOperation {
        let Some(service_signing_key) = self.service_keys.get(service_id) else {
            panic!("No existing service found for {}", service_id)
        };

        let op = Operation::new_create_account(
            id.to_string(),
            &signing_key,
            service_id.to_string(),
            service_signing_key,
        )
        .expect("Creating account operation should work");

        UncommittedOperation {
            operation: op,
            builder: self,
            post_commit_action: PostCommitAction::RememberAccountKey(id.to_string(), signing_key),
        }
    }

    pub fn add_random_key_verified_with_root(&mut self, id: &str) -> UncommittedOperation {
        let Some(account_signing_key) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        self.add_random_key(id, &account_signing_key, 0)
    }

    pub fn add_random_key(
        &mut self,
        id: &str,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedOperation {
        let random_key = create_mock_signing_key().into();
        self.add_key(id, random_key, signing_key, key_idx)
    }

    pub fn add_key_verified_with_root(
        &mut self,
        id: &str,
        key: VerifyingKey,
    ) -> UncommittedOperation {
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
    ) -> UncommittedOperation {
        let hashed_id = Digest::hash(id);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        let Ok(Found(hc, _)) = self.tree.get(key_hash) else {
            panic!("No existing hashchain found for {}", id)
        };

        let op = Operation::new_add_key(id.to_string(), key, hc.last_hash(), signing_key, key_idx)
            .expect("Creating add-key operation should work");

        UncommittedOperation {
            operation: op,
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }

    pub fn revoke_key_verified_with_root(
        &mut self,
        id: &str,
        key: VerifyingKey,
    ) -> UncommittedOperation {
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
    ) -> UncommittedOperation {
        let hashed_id = Digest::hash(id);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        let Ok(Found(hc, _)) = self.tree.get(key_hash) else {
            panic!("No existing hashchain found for {}", id)
        };

        let op =
            Operation::new_revoke_key(id.to_string(), key, hc.last_hash(), signing_key, key_idx)
                .expect("Creating account operation should work");

        UncommittedOperation {
            operation: op,
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }

    pub fn add_signed_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: SignatureBundle,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedOperation {
        self.add_data(id, value, Some(value_signature), signing_key, key_idx)
    }

    pub fn add_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: SignatureBundle,
    ) -> UncommittedOperation {
        self.add_data_verified_with_root(id, value, Some(value_signature))
    }

    pub fn add_unsigned_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedOperation {
        self.add_data(id, value, None, signing_key, key_idx)
    }

    pub fn add_unsigned_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
    ) -> UncommittedOperation {
        self.add_data_verified_with_root(id, value, None)
    }

    fn add_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: Option<SignatureBundle>,
    ) -> UncommittedOperation {
        let Some(account_signing_key) = self.account_keys.get(id).cloned() else {
            panic!("No existing account key for {}", id)
        };

        self.add_data(id, value, value_signature, &account_signing_key, 0)
    }

    fn add_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: Option<SignatureBundle>,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedOperation {
        let hashed_id = Digest::hash(id);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        let Ok(Found(hc, _)) = self.tree.get(key_hash) else {
            panic!("No existing hashchain found for {}", id)
        };

        let op = Operation::new_add_signed_data(
            id.to_string(),
            value,
            value_signature,
            hc.last_hash(),
            signing_key,
            key_idx,
        )
        .expect("Creating add-data operation should work");

        UncommittedOperation {
            operation: op,
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }
}
