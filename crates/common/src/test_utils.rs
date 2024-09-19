use crate::{
    hashchain::{Hashchain, HashchainEntry},
    operation::{KeyOperationArgs, Operation, PublicKey, SignatureBundle},
    tree::{hash, Digest, InsertProof, KeyDirectoryTree, SnarkableTree, UpdateProof},
};
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, SigningKey};
use jmt::{mock::MockTreeStore, KeyHash};
use rand::{rngs::StdRng, Rng};
use std::{collections::HashSet, sync::Arc};

pub struct TestTreeState {
    pub tree: KeyDirectoryTree<MockTreeStore>,
    inserted_keys: HashSet<KeyHash>,
}

impl TestTreeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_account(&mut self, key: String) -> (KeyHash, Hashchain) {
        let hc = create_mock_hashchain(key.as_str());
        let key = hc.get_keyhash();

        (key, hc)
    }

    pub fn insert_account(&mut self, key: KeyHash, hc: Hashchain) -> Result<InsertProof> {
        if self.inserted_keys.contains(&key) {
            return Err(anyhow!("{:?} already contained in tree", key));
        }

        let proof = self.tree.insert(key, hc).expect("Insert should succeed");
        self.inserted_keys.insert(key);

        Ok(proof)
    }

    pub fn update_account(&mut self, key: KeyHash, hc: Hashchain) -> Result<UpdateProof> {
        if !self.inserted_keys.contains(&key) {
            return Err(anyhow!("{:?} not found in tree", key));
        }

        let proof = self.tree.update(key, hc).expect("Update should succeed");
        Ok(proof)
    }
}

impl Default for TestTreeState {
    fn default() -> Self {
        let store = Arc::new(MockTreeStore::default());
        let tree = KeyDirectoryTree::new(store);
        Self {
            tree,
            inserted_keys: HashSet::new(),
        }
    }
}

pub fn create_random_insert(state: &mut TestTreeState, rng: &mut StdRng) -> InsertProof {
    loop {
        let random_string: String = (0..10)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();
        let hc = Hashchain::new(random_string);
        let key = hc.get_keyhash();

        if !state.inserted_keys.contains(&key) {
            let proof = state.tree.insert(key, hc).expect("Insert should succeed");
            state.inserted_keys.insert(key);
            println!("inserted key: {key:?}");
            return proof;
        }
    }
}

pub fn create_random_update(state: &mut TestTreeState, rng: &mut StdRng) -> UpdateProof {
    if state.inserted_keys.is_empty() {
        panic!("No keys have been inserted yet. Cannot perform update.");
    }

    let key = *state
        .inserted_keys
        .iter()
        .nth(rng.gen_range(0..state.inserted_keys.len()))
        .unwrap();
    let mut hc = state.tree.get(key).unwrap().unwrap();

    let signing_key = SigningKey::generate(rng);
    let verifying_key = signing_key.verifying_key();
    let public_key = PublicKey::Ed25519(verifying_key.to_bytes().to_vec());

    let random_string: String = (0..10)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();

    let signature = create_mock_signature(&signing_key, random_string.as_bytes());

    hc.add(public_key, signature)
        .expect("Adding to hashchain should succeed");
    println!("updated key: {key:?}");

    state.tree.update(key, hc).expect("Update should succeed")
}

pub fn create_mock_signature(signing_key: &SigningKey, message: &[u8]) -> SignatureBundle {
    let signature = signing_key.sign(message);
    SignatureBundle {
        key_idx: 0,
        signature: signature.to_bytes().to_vec(),
    }
}

pub fn create_mock_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::thread_rng())
}

pub fn create_mock_hashchain(id: &str) -> Hashchain {
    let mut hc = Hashchain::new(id.to_string());
    let signing_key = create_mock_signing_key();
    let public_key = PublicKey::Ed25519(signing_key.verifying_key().to_bytes().to_vec());
    let signature = create_mock_signature(&signing_key, id.as_bytes());

    let op = Operation::AddKey(KeyOperationArgs {
        id: id.to_string(),
        value: public_key.clone(),
        signature,
    });

    hc.push(op).unwrap();
    hc
}

pub fn create_mock_chain_entry(signing_key: &SigningKey, previous_hash: Digest) -> HashchainEntry {
    let operation = Operation::AddKey(KeyOperationArgs {
        id: "test_id".to_string(),
        value: PublicKey::Ed25519(signing_key.verifying_key().to_bytes().to_vec()),
        signature: create_mock_signature(signing_key, b"test_id"),
    });

    HashchainEntry::new(operation, previous_hash)
}

pub fn create_add_key_operation_with_test_value(id: &str, signing_key: &SigningKey) -> Operation {
    Operation::AddKey(KeyOperationArgs {
        id: id.to_string(),
        value: PublicKey::Ed25519(signing_key.verifying_key().to_bytes().to_vec()),
        signature: create_mock_signature(signing_key, id.as_bytes()),
    })
}
