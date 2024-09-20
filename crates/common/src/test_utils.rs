use crate::{
    hashchain::{Hashchain, HashchainEntry},
    operation::{KeyOperationArgs, Operation, PublicKey, SignatureBundle},
    tree::{Digest, InsertProof, KeyDirectoryTree, SnarkableTree, UpdateProof},
};
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, SigningKey};
use jmt::{mock::MockTreeStore, KeyHash};
use rand::{rngs::StdRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub struct TestTreeState {
    pub tree: KeyDirectoryTree<MockTreeStore>,
    pub signing_keys: HashMap<String, SigningKey>,
    inserted_keys: HashSet<KeyHash>,
}

#[derive(Clone)]
pub struct TestAccount {
    pub key_hash: KeyHash,
    pub hashchain: Hashchain,
}

impl TestTreeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_account(&mut self, key: String) -> TestAccount {
        let signing_key = create_mock_signing_key();
        self.signing_keys.insert(key.clone(), signing_key.clone());
        let hashchain = create_mock_hashchain(key.as_str(), &signing_key);
        let key_hash = hashchain.get_keyhash();

        TestAccount {
            key_hash,
            hashchain,
        }
    }

    pub fn insert_account(&mut self, account: TestAccount) -> Result<InsertProof> {
        if self.inserted_keys.contains(&account.key_hash) {
            return Err(anyhow!("{:?} already contained in tree", account.key_hash));
        }

        let proof = self.tree.insert(account.key_hash, account.hashchain).expect("Insert should succeed");
        self.inserted_keys.insert(account.key_hash);

        Ok(proof)
    }

    pub fn update_account(&mut self, account: TestAccount) -> Result<UpdateProof> {
        if !self.inserted_keys.contains(&account.key_hash) {
            return Err(anyhow!("{:?} not found in tree", account.key_hash));
        }

        let proof = self.tree.update(account.key_hash, account.hashchain).expect("Update should succeed");
        Ok(proof)
    }

    pub fn add_key_to_account(
        &mut self,
        account: &mut TestAccount,
    ) -> Result<(), anyhow::Error> {
        let signing_key_to_add = create_mock_signing_key();
        let pub_key = PublicKey::Ed25519(signing_key_to_add.verifying_key().to_bytes().to_vec());
        let operation_to_sign = Operation::AddKey(KeyOperationArgs {
            id: account.hashchain.id.clone(),
            value: pub_key.clone(),
            signature: SignatureBundle {
                key_idx: 0,
                signature: Vec::new(),
            },
        });
    
        let message = bincode::serialize(&operation_to_sign)?;
        let signature = SignatureBundle {
            key_idx: 0,
            signature: self
                .signing_keys
                .get(&account.hashchain.id)
                .unwrap()
                .sign(&message)
                .to_vec(),
        };
    
        let operation = Operation::AddKey(KeyOperationArgs {
            id: account.hashchain.id.clone(),
            value: pub_key,
            signature
        });
    
        account.hashchain.add(operation);
    
        Ok(())
    }
}

impl Default for TestTreeState {
    fn default() -> Self {
        let store = Arc::new(MockTreeStore::default());
        let tree = KeyDirectoryTree::new(store);
        Self {
            tree,
            inserted_keys: HashSet::new(),
            signing_keys: HashMap::new(),
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

    let operation_to_sign = Operation::AddKey(KeyOperationArgs {
        id: hc.id.clone(),
        value: public_key.clone(),
        signature: SignatureBundle {
            key_idx: 0,
            signature: Vec::new(),
        },
    });

    let message = bincode::serialize(&operation_to_sign).unwrap();
    let signature = state
        .signing_keys
        .get(&hc.id)
        .ok_or_else(|| anyhow::anyhow!("Signing key not found for hashchain"))
        .unwrap()
        .sign(&message);

    let final_operation = Operation::AddKey(KeyOperationArgs {
        id: hc.id.clone(),
        value: public_key,
        signature: SignatureBundle {
            key_idx: 0,
            signature: signature.to_bytes().to_vec(),
        },
    });

    hc.add(final_operation)
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

pub fn create_mock_hashchain(id: &str, signing_key: &SigningKey) -> Hashchain {
    let mut hc = Hashchain::new(id.to_string());
    let public_key = PublicKey::Ed25519(signing_key.verifying_key().to_bytes().to_vec());
    let signature = create_mock_signature(signing_key, id.as_bytes());

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


