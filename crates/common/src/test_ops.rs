use std::{collections::HashMap, sync::Arc};

use jmt::{mock::MockTreeStore, KeyHash};

use crate::{
    digest::Digest,
    hashchain::HashchainEntry,
    hasher::Hasher,
    keys::{SigningKey, VerifyingKey},
    operation::{ServiceChallenge, ServiceChallengeInput, SignatureBundle},
    request::PendingRequest,
    test_utils::create_mock_signing_key,
    tree::{HashchainResponse::*, KeyDirectoryTree, SnarkableTree},
};
enum PostCommitAction {
    UpdateStorageOnly,
    RememberServiceKey(String, SigningKey),
    RememberAccountKey(String, SigningKey),
}

pub struct UncommittedRequest<'a> {
    request: PendingRequest,
    builder: &'a mut RequestBuilder,
    post_commit_action: PostCommitAction,
}

impl UncommittedRequest<'_> {
    pub fn ex(self) -> PendingRequest {
        self.builder
            .tree
            .process_entry(self.request.clone())
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

        self.request
    }

    pub fn op(self) -> PendingRequest {
        self.request
    }
}

pub struct RequestBuilder {
    /// Simulated hashchain storage that is mutated when operations are applied
    tree: Box<dyn SnarkableTree>,
    /// Remembers private keys of services to simulate account creation via an external service
    service_keys: HashMap<String, SigningKey>,
    /// Remembers private keys of accounts to simulate actions on behalf of these accounts
    account_keys: HashMap<String, SigningKey>,
}

impl Default for RequestBuilder {
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

impl RequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_service_with_random_keys(&mut self, id: &str) -> UncommittedRequest {
        let random_service_challenge_key = create_mock_signing_key();
        let random_service_signing_key = create_mock_signing_key();
        self.register_service(id, random_service_challenge_key, random_service_signing_key)
    }

    pub fn register_service(
        &mut self,
        id: &str,
        challenge_key: SigningKey,
        signing_key: SigningKey,
    ) -> UncommittedRequest {
        let entry = HashchainEntry::new_register_service(
            id.to_string(),
            ServiceChallenge::from(challenge_key.clone()),
            signing_key.verifying_key(),
            &signing_key,
        );

        UncommittedRequest {
            request: PendingRequest {
                id: id.to_string(),
                entry,
            },
            builder: self,
            post_commit_action: PostCommitAction::RememberServiceKey(id.to_string(), challenge_key),
        }
    }

    pub fn create_account_with_random_key(
        &mut self,
        id: &str,
        service_id: &str,
    ) -> UncommittedRequest {
        let random_signing_key = create_mock_signing_key();
        self.create_account(id, service_id, random_signing_key)
    }

    pub fn create_account(
        &mut self,
        id: &str,
        service_id: &str,
        signing_key: SigningKey,
    ) -> UncommittedRequest {
        let Some(service_signing_key) = self.service_keys.get(service_id) else {
            panic!("No existing service found for {}", service_id)
        };

        // Simulate some external service signing account creation credentials
        let hash = Digest::hash_items(&[
            id.as_bytes(),
            service_id.as_bytes(),
            &signing_key.verifying_key().as_bytes(),
        ]);
        let signature = service_signing_key.sign(&hash.to_bytes());

        let entry = HashchainEntry::new_create_account(
            id.to_string(),
            service_id.to_string(),
            ServiceChallengeInput::Signed(signature),
            signing_key.verifying_key(),
            &signing_key,
        );

        UncommittedRequest {
            request: PendingRequest {
                id: id.to_string(),
                entry,
            },
            builder: self,
            post_commit_action: PostCommitAction::RememberAccountKey(id.to_string(), signing_key),
        }
    }

    pub fn add_random_key_verified_with_root(&mut self, id: &str) -> UncommittedRequest {
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
    ) -> UncommittedRequest {
        let random_key = create_mock_signing_key().verifying_key();
        self.add_key(id, random_key, signing_key, key_idx)
    }

    pub fn add_key_verified_with_root(
        &mut self,
        id: &str,
        key: VerifyingKey,
    ) -> UncommittedRequest {
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
    ) -> UncommittedRequest {
        let hashed_id = Digest::hash(id);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        let Ok(Found(hc, _)) = self.tree.get(key_hash) else {
            panic!("No existing hashchain found for {}", id)
        };

        let entry = HashchainEntry::new_add_key(key, hc.last_hash(), signing_key, key_idx);

        UncommittedRequest {
            request: PendingRequest {
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
    ) -> UncommittedRequest {
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
    ) -> UncommittedRequest {
        let hashed_id = Digest::hash(id);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        let Ok(Found(hc, _)) = self.tree.get(key_hash) else {
            panic!("No existing hashchain found for {}", id)
        };

        let entry = HashchainEntry::new_revoke_key(key, hc.last_hash(), signing_key, key_idx);

        UncommittedRequest {
            request: PendingRequest {
                id: id.to_string(),
                entry,
            },
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
    ) -> UncommittedRequest {
        self.add_data(id, value, Some(value_signature), signing_key, key_idx)
    }

    pub fn add_signed_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: SignatureBundle,
    ) -> UncommittedRequest {
        self.add_data_verified_with_root(id, value, Some(value_signature))
    }

    pub fn add_unsigned_data(
        &mut self,
        id: &str,
        value: Vec<u8>,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> UncommittedRequest {
        self.add_data(id, value, None, signing_key, key_idx)
    }

    pub fn add_unsigned_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
    ) -> UncommittedRequest {
        self.add_data_verified_with_root(id, value, None)
    }

    fn add_data_verified_with_root(
        &mut self,
        id: &str,
        value: Vec<u8>,
        value_signature: Option<SignatureBundle>,
    ) -> UncommittedRequest {
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
    ) -> UncommittedRequest {
        let hashed_id = Digest::hash(id);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        let Ok(Found(hc, _)) = self.tree.get(key_hash) else {
            panic!("No existing hashchain found for {}", id)
        };

        let entry = HashchainEntry::new_add_data(
            data,
            data_signature,
            hc.last_hash(),
            signing_key,
            key_idx,
        );

        UncommittedRequest {
            request: PendingRequest {
                id: id.to_string(),
                entry,
            },
            builder: self,
            post_commit_action: PostCommitAction::UpdateStorageOnly,
        }
    }
}
