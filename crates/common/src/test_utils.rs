use crate::{
    digest::Digest,
    hashchain::Hashchain,
    hasher::Hasher,
    keys::{SigningKey, VerifyingKey},
    operation::{ServiceChallenge, ServiceChallengeInput, SignatureBundle},
    tree::{
        HashchainResponse::*, InsertProof, KeyDirectoryTree, Proof, SnarkableTree, UpdateProof,
    },
};
use anyhow::{anyhow, Result};
#[cfg(not(feature = "secp256k1"))]
use ed25519_consensus::SigningKey as Ed25519SigningKey;
use jmt::{mock::MockTreeStore, KeyHash};
use rand::{
    rngs::{OsRng, StdRng},
    Rng,
};
#[cfg(feature = "secp256k1")]
use secp256k1::SecretKey as Secp256k1SigningKey;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub struct TestTreeState {
    pub tree: KeyDirectoryTree<MockTreeStore>,
    pub signing_keys: HashMap<String, SigningKey>,
    inserted_keys: HashSet<String>,
    pub services: HashMap<String, Service>,
}

#[derive(Clone)]
pub struct TestAccount {
    pub id: String,
    pub key_hash: KeyHash,
    pub hashchain: Hashchain,
}

#[derive(Clone)]
pub struct Service {
    pub id: String,
    pub sk: SigningKey,
    pub vk: VerifyingKey,
    pub registration: TestAccount,
}

impl TestTreeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_service(&mut self, service_id: String) -> Service {
        let service_challenge_key = create_mock_signing_key();
        let service_signing_key = create_mock_signing_key();

        let mut hashchain = Hashchain::empty();

        hashchain
            .register_service(
                service_id.clone(),
                ServiceChallenge::from(service_challenge_key.clone()),
                service_signing_key.verifying_key(),
                &service_signing_key,
            )
            .unwrap();

        let hashed_id = Digest::hash(&service_id);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        Service {
            id: service_id.clone(),
            sk: service_challenge_key.clone(),
            vk: service_challenge_key.verifying_key(),
            registration: TestAccount {
                id: service_id,
                key_hash,
                hashchain,
            },
        }
    }

    pub fn create_account(&mut self, id: String, service: Service) -> TestAccount {
        let signing_key = create_mock_signing_key();
        self.signing_keys.insert(id.clone(), signing_key.clone());

        // Simulate some external service signing account creation credentials
        let hash = Digest::hash_items(&[
            id.as_bytes(),
            service.id.as_bytes(),
            &signing_key.verifying_key().as_bytes(),
        ]);
        let signature = service.sk.sign(&hash.to_bytes());

        let mut hashchain = Hashchain::empty();
        hashchain
            .create_account(
                id.clone(),
                service.id.clone(),
                ServiceChallengeInput::Signed(signature),
                signing_key.verifying_key(),
                &signing_key,
            )
            .unwrap();

        let hashed_id = Digest::hash(&id);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        TestAccount {
            id,
            key_hash,
            hashchain,
        }
    }

    pub fn insert_account(&mut self, account: TestAccount) -> Result<InsertProof> {
        if self.inserted_keys.contains(&account.id) {
            return Err(anyhow!("{:?} already contained in tree", account.id));
        }

        let proof =
            self.tree.process_entry(&account.id, account.hashchain.last().unwrap().clone())?;
        if let Proof::Insert(insert_proof) = proof {
            self.inserted_keys.insert(account.id);
            return Ok(*insert_proof);
        }
        Err(anyhow!("Insert proof not returned"))
    }

    pub fn update_account(&mut self, account: TestAccount) -> Result<UpdateProof> {
        if !self.inserted_keys.contains(&account.id) {
            return Err(anyhow!("{:?} not found in tree", account.id));
        }

        let proof =
            self.tree.process_entry(&account.id, account.hashchain.last().unwrap().clone())?;
        if let Proof::Update(update_proof) = proof {
            return Ok(*update_proof);
        }
        Err(anyhow!("Update proof not returned"))
    }

    pub fn add_key_to_account(&mut self, account: &mut TestAccount) -> Result<(), anyhow::Error> {
        let signing_key_to_add = create_mock_signing_key();
        let key_to_add = signing_key_to_add.verifying_key();

        account
            .hashchain
            .add_key(key_to_add, self.signing_keys.get(&account.id).unwrap(), 0)
            .unwrap();
        Ok(())
    }

    pub fn add_unsigned_data_to_account(
        &mut self,
        data: &[u8],
        account: &mut TestAccount,
    ) -> Result<()> {
        self.add_data_to_account(data, account, None)
    }

    pub fn add_signed_data_to_account(
        &mut self,
        data: &[u8],
        account: &mut TestAccount,
    ) -> Result<()> {
        let random_signing_key = create_mock_signing_key();
        self.add_data_to_account(data, account, Some(&random_signing_key))
    }

    fn add_data_to_account(
        &mut self,
        data: &[u8],
        account: &mut TestAccount,
        signing_key: Option<&SigningKey>,
    ) -> Result<()> {
        let signature_bundle = signing_key.map(|sk| SignatureBundle {
            verifying_key: sk.verifying_key(),
            signature: sk.sign(data),
        });

        let signing_key = self.signing_keys.get(&account.id).unwrap();

        account.hashchain.add_data(data.to_vec(), signature_bundle, signing_key, 0)?;
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
            services: HashMap::new(),
        }
    }
}

pub fn create_random_insert(state: &mut TestTreeState, rng: &mut StdRng) -> InsertProof {
    loop {
        let random_string: String =
            (0..10).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
        let sk = create_mock_signing_key();

        let (_, service) =
            state.services.iter().nth(rng.gen_range(0..state.services.len())).unwrap();

        // Simulate some external service signing account creation credentials
        let hash = Digest::hash_items(&[
            random_string.as_bytes(),
            service.id.as_bytes(),
            &sk.verifying_key().as_bytes(),
        ]);
        let signature = service.sk.sign(&hash.to_bytes());

        let hashed_id = Digest::hash(&random_string);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        let entry = Hashchain::empty()
            .create_account(
                random_string.clone(),
                service.id.clone(),
                ServiceChallengeInput::Signed(signature),
                sk.verifying_key(),
                &sk,
            )
            .unwrap();

        if !state.inserted_keys.contains(&random_string) {
            let proof = state.tree.insert(key_hash, entry).expect("Insert should succeed");
            state.inserted_keys.insert(random_string.clone());
            state.signing_keys.insert(random_string, sk);
            return proof;
        }
    }
}

pub fn create_random_update(state: &mut TestTreeState, rng: &mut StdRng) -> UpdateProof {
    if state.inserted_keys.is_empty() {
        panic!("No keys have been inserted yet. Cannot perform update.");
    }

    let key = state.inserted_keys.iter().nth(rng.gen_range(0..state.inserted_keys.len())).unwrap();

    let hashed_id = Digest::hash(key);
    let key_hash = KeyHash::with::<Hasher>(hashed_id);

    let Found(mut hc, _) = state.tree.get(key_hash).unwrap() else {
        panic!("No response found for key. Cannot perform update.");
    };

    let signing_key = create_mock_signing_key();
    let verifying_key = signing_key.verifying_key();

    let signer = state
        .signing_keys
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("Signing key not found for hashchain"))
        .unwrap();

    let entry = hc.add_key(verifying_key, signer, 0).unwrap();

    let Proof::Update(update_proof) =
        state.tree.process_entry(key, entry).expect("Processing operation should succeed")
    else {
        panic!("No update proof returned.");
    };

    *update_proof
}

#[cfg(not(feature = "secp256k1"))]
pub fn create_mock_signing_key() -> SigningKey {
    SigningKey::Ed25519(Box::new(Ed25519SigningKey::new(OsRng)))
}

#[cfg(feature = "secp256k1")]
pub fn create_mock_signing_key() -> SigningKey {
    SigningKey::Secp256k1(Secp256k1SigningKey::new(&mut OsRng))
}
