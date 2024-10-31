use crate::{
    digest::Digest,
    hashchain::Hashchain,
    hasher::Hasher,
    keys::{SigningKey, VerifyingKey},
    operation::{Operation, ServiceChallenge, SignatureBundle},
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
    inserted_keys: HashSet<KeyHash>,
    pub services: HashMap<String, Service>,
}

#[derive(Clone)]
pub struct TestAccount {
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
        let service_key = create_mock_signing_key();

        let hashchain = Hashchain::from_operation(Operation::new_register_service(
            service_id.clone(),
            ServiceChallenge::from(service_key.clone()),
        ))
        .unwrap();

        let key_hash = hashchain.get_keyhash();

        Service {
            id: service_id,
            sk: service_key.clone(),
            vk: service_key.verifying_key(),
            registration: TestAccount {
                key_hash,
                hashchain,
            },
        }
    }

    pub fn create_account(&mut self, key: String, service: Service) -> TestAccount {
        let signing_key = create_mock_signing_key();
        self.signing_keys.insert(key.clone(), signing_key.clone());
        let hashchain = create_new_hashchain(key.as_str(), &signing_key, service);
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

        let proof = self.tree.process_operation(&account.hashchain.last().unwrap().operation)?;
        if let Proof::Insert(insert_proof) = proof {
            self.inserted_keys.insert(account.key_hash);
            return Ok(*insert_proof);
        }
        Err(anyhow!("Insert proof not returned"))
    }

    pub fn update_account(&mut self, account: TestAccount) -> Result<UpdateProof> {
        if !self.inserted_keys.contains(&account.key_hash) {
            return Err(anyhow!("{:?} not found in tree", account.key_hash));
        }

        let proof = self.tree.process_operation(&account.hashchain.last().unwrap().operation)?;
        if let Proof::Update(update_proof) = proof {
            return Ok(*update_proof);
        }
        Err(anyhow!("Update proof not returned"))
    }

    pub fn add_key_to_account(&mut self, account: &mut TestAccount) -> Result<(), anyhow::Error> {
        let signing_key_to_add = create_mock_signing_key();
        let key_to_add = signing_key_to_add.verifying_key();
        let op = Operation::new_add_key(
            account.hashchain.id.clone(),
            key_to_add.clone(),
            account.hashchain.last_hash(),
            self.signing_keys.get(&account.hashchain.id).unwrap(),
            0,
        )?;

        account.hashchain.perform_operation(op).unwrap();
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

        let op_signing_key = self.signing_keys.get(&account.hashchain.id).unwrap();

        let prev_hash = account.hashchain.last_hash();

        let op = Operation::new_add_signed_data(
            account.hashchain.id.clone(),
            data.to_vec(),
            signature_bundle,
            prev_hash,
            op_signing_key,
            0,
        )?;

        account.hashchain.perform_operation(op).unwrap();
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

        let operation = Operation::new_create_account(
            random_string.clone(),
            &sk,
            service.id.clone(),
            &service.sk,
        )
        .expect("Creating account operation should succeed");

        let hashed_id = Digest::hash(&random_string);
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        if !state.inserted_keys.contains(&key_hash) {
            let proof = state.tree.insert(key_hash, operation).expect("Insert should succeed");
            state.inserted_keys.insert(key_hash);
            state.signing_keys.insert(random_string, sk);
            return proof;
        }
    }
}

pub fn create_random_update(state: &mut TestTreeState, rng: &mut StdRng) -> UpdateProof {
    if state.inserted_keys.is_empty() {
        panic!("No keys have been inserted yet. Cannot perform update.");
    }

    let key = *state.inserted_keys.iter().nth(rng.gen_range(0..state.inserted_keys.len())).unwrap();

    let Found(hc, _) = state.tree.get(key).unwrap() else {
        panic!("No response found for key. Cannot perform update.");
    };

    let signing_key = create_mock_signing_key();
    let verifying_key = signing_key.verifying_key();

    let signer = state
        .signing_keys
        .get(&hc.id)
        .ok_or_else(|| anyhow::anyhow!("Signing key not found for hashchain"))
        .unwrap();

    let operation = Operation::new_add_key(
        hc.id.clone(),
        verifying_key.clone(),
        hc.last_hash(),
        signer,
        0,
    )
    .unwrap();

    let Proof::Update(update_proof) =
        state.tree.process_operation(&operation).expect("Processing operation should succeed")
    else {
        panic!("No update proof returned.");
    };

    update_proof
}

#[cfg(not(feature = "secp256k1"))]
pub fn create_mock_signing_key() -> SigningKey {
    SigningKey::Ed25519(Box::new(Ed25519SigningKey::new(OsRng)))
}

#[cfg(feature = "secp256k1")]
pub fn create_mock_signing_key() -> SigningKey {
    SigningKey::Secp256k1(Secp256k1SigningKey::new(&mut OsRng))
}

pub fn create_new_hashchain(id: &str, signing_key: &SigningKey, service: Service) -> Hashchain {
    let op = Operation::new_create_account(id.to_string(), signing_key, service.id, &service.sk)
        .unwrap();
    Hashchain::from_operation(op.clone()).unwrap()
}
