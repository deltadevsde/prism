use anyhow::{anyhow, bail, Context, Result};
use bincode;
use bls12_381::Scalar;
use jmt::{
    proof::{SparseMerkleProof, UpdateMerkleProof},
    storage::{NodeBatch, TreeReader, TreeUpdateBatch, TreeWriter},
    JellyfishMerkleTree, KeyHash, RootHash, SimpleHasher,
};
use prism_errors::DatabaseError;
use serde::{ser::SerializeTupleStruct, Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    hashchain::Hashchain,
    operation::{CreateAccountArgs, KeyOperationArgs, Operation, ServiceChallengeInput},
};

pub const SPARSE_MERKLE_PLACEHOLDER_HASH: Digest =
    Digest::new(*b"SPARSE_MERKLE_PLACEHOLDER_HASH__");

#[derive(Debug, Clone, Default)]
pub struct Hasher(sha2::Sha256);

impl Serialize for Hasher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_tuple_struct("Sha256Wrapper", 0)?.end()
    }
}

impl<'de> Deserialize<'de> for Hasher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Sha256WrapperVisitor;

        impl<'de> serde::de::Visitor<'de> for Sha256WrapperVisitor {
            type Value = Hasher;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a Sha256Wrapper")
            }

            fn visit_seq<A>(self, _seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                Ok(Hasher::default())
            }
        }

        deserializer.deserialize_tuple_struct("Sha256Wrapper", 0, Sha256WrapperVisitor)
    }
}

impl SimpleHasher for Hasher {
    fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        self.0.finalize()
    }
}

pub fn hash(data: &[u8]) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(data);
    Digest(hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

// implementing it for now to get things to compile, curve choice will be made later
impl TryFrom<Digest> for Scalar {
    type Error = anyhow::Error;

    fn try_from(value: Digest) -> Result<Scalar, Self::Error> {
        let mut byte_array = [0u8; 32];
        byte_array.copy_from_slice(value.as_ref());
        byte_array.reverse();

        let val =
            [
                u64::from_le_bytes(byte_array[0..8].try_into().map_err(|_| {
                    anyhow!(format!("slice to array: [0..8] for digest: {value:?}"))
                })?),
                u64::from_le_bytes(byte_array[8..16].try_into().map_err(|_| {
                    anyhow!(format!("slice to array: [8..16] for digest: {value:?}"))
                })?),
                u64::from_le_bytes(byte_array[16..24].try_into().map_err(|_| {
                    anyhow!(format!("slice to array: [16..24] for digest: {value:?}"))
                })?),
                u64::from_le_bytes(byte_array[24..32].try_into().map_err(|_| {
                    anyhow!(format!("slice to array: [24..32] for digest: {value:?}"))
                })?),
            ];

        Ok(Scalar::from_raw(val))
    }
}

impl From<Digest> for RootHash {
    fn from(val: Digest) -> RootHash {
        RootHash::from(val.0)
    }
}

impl From<RootHash> for Digest {
    fn from(val: RootHash) -> Digest {
        Digest(val.0)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Digest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes)
            .map_err(|e| anyhow!(format!("Invalid Format: {e}")))?;
        Ok(Digest(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Batch {
    pub prev_root: Digest,
    pub new_root: Digest,

    pub proofs: Vec<Proof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Proof {
    Update(UpdateProof),
    Insert(InsertProof),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonMembershipProof {
    pub root: Digest,
    pub proof: SparseMerkleProof<Hasher>,
    pub key: KeyHash,
}

impl NonMembershipProof {
    pub fn verify(&self) -> Result<()> {
        self.proof.verify_nonexistence(self.root.into(), self.key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertProof {
    pub non_membership_proof: NonMembershipProof,

    pub new_root: Digest,
    pub membership_proof: SparseMerkleProof<Hasher>,
    pub value: Hashchain,
}

impl InsertProof {
    pub fn verify(&self) -> Result<()> {
        self.non_membership_proof
            .verify()
            .context("Invalid NonMembershipProof")?;

        let value = bincode::serialize(&self.value).unwrap();

        self.membership_proof.clone().verify_existence(
            self.new_root.into(),
            self.non_membership_proof.key,
            value,
        )?;

        self.value.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProof {
    pub old_root: RootHash,
    pub new_root: RootHash,

    pub key: KeyHash,
    pub new_value: Hashchain,

    pub proof: UpdateMerkleProof<Hasher>,
}

impl UpdateProof {
    pub fn verify(&self) -> Result<()> {
        let new_value = bincode::serialize(&self.new_value)?;

        self.proof.clone().verify_update(
            self.old_root,
            self.new_root,
            vec![(self.key, Some(new_value))],
        )?;

        self.new_value.validate()
    }
}

pub trait SnarkableTree {
    fn process_operation(&mut self, operation: &Operation) -> Result<Proof>;
    fn insert(&mut self, key: KeyHash, value: Hashchain) -> Result<InsertProof>;
    fn update(&mut self, key: KeyHash, value: Hashchain) -> Result<UpdateProof>;
    fn get(&self, key: KeyHash) -> Result<Result<Hashchain, NonMembershipProof>>;
}

pub struct KeyDirectoryTree<S>
where
    S: TreeReader + TreeWriter,
{
    jmt: JellyfishMerkleTree<Arc<S>, Hasher>,
    pending_batch: Option<NodeBatch>,
    epoch: u64,
    db: Arc<S>,
}

impl<S> KeyDirectoryTree<S>
where
    S: TreeReader + TreeWriter,
{
    pub fn new(store: Arc<S>) -> Self {
        let tree = Self {
            db: store.clone(),
            jmt: JellyfishMerkleTree::<Arc<S>, Hasher>::new(store),
            pending_batch: None,
            epoch: 0,
        };
        let (_, batch) = tree
            .jmt
            .put_value_set(vec![(KeyHash(SPARSE_MERKLE_PLACEHOLDER_HASH.0), None)], 0)
            .unwrap();
        tree.db.write_node_batch(&batch.node_batch).unwrap();
        tree
    }

    pub fn get_commitment(&self) -> Result<Digest> {
        let root = self.get_current_root()?;
        Ok(Digest(root.0))
    }

    fn queue_batch(&mut self, batch: TreeUpdateBatch) {
        match self.pending_batch {
            Some(ref mut pending_batch) => pending_batch.merge(batch.node_batch),
            None => self.pending_batch = Some(batch.node_batch),
        }
    }

    fn write_batch(&mut self) -> Result<()> {
        if let Some(batch) = self.pending_batch.take() {
            self.db.write_node_batch(&batch)?;
            self.epoch += 1;
        }
        Ok(())
    }

    pub fn get_current_root(&self) -> Result<RootHash> {
        self.jmt
            .get_root_hash(self.epoch)
            .map_err(|e| anyhow!("Failed to get root hash: {}", e))
    }

    fn serialize_value(value: &Hashchain) -> Result<Vec<u8>> {
        bincode::serialize(value).map_err(|e| anyhow!("Failed to serialize value: {}", e))
    }

    fn deserialize_value(bytes: &[u8]) -> Result<Hashchain> {
        bincode::deserialize::<Hashchain>(bytes)
            .map_err(|e| anyhow!("Failed to deserialize value: {}", e))
    }
}

impl<S> SnarkableTree for KeyDirectoryTree<S>
where
    S: TreeReader + TreeWriter,
{
    fn process_operation(&mut self, operation: &Operation) -> Result<Proof> {
        match operation {
            Operation::AddKey(KeyOperationArgs { id, .. })
            | Operation::RevokeKey(KeyOperationArgs { id, .. }) => {
                let hashed_id = hash(id.as_bytes());
                let key_hash = KeyHash::with::<Hasher>(hashed_id);

                let mut current_chain = self
                    .get(key_hash)?
                    .map_err(|_| anyhow!("Failed to get hashchain for ID {}", id))?;

                current_chain.perform_operation(operation.clone())?;

                debug!("updating hashchain for user id {}", id.clone());
                let proof = self.update(key_hash, current_chain.clone())?;

                Ok(Proof::Update(proof))
            }
            Operation::CreateAccount(CreateAccountArgs {
                id,
                value,
                signature,
                service_id,
                challenge,
            }) => {
                let hashed_id = hash(id.as_bytes());
                let key_hash = KeyHash::with::<Hasher>(hashed_id);

                match &challenge {
                    ServiceChallengeInput::Signed(_) => debug!("Signature verification for service challenge gate not yet implemented. Skipping verification.")
                };

                // hashchain should not already exist
                if self.get(key_hash)?.is_ok() {
                    bail!(DatabaseError::NotFoundError(format!(
                        "empty slot for ID {}",
                        id
                    )));
                }

                debug!("creating new hashchain for user id {}", id);
                let mut chain = Hashchain::new(id.clone());
                chain.create_account(
                    value.clone(),
                    signature.clone(),
                    service_id.clone(),
                    challenge.clone(),
                )?;

                Ok(Proof::Insert(
                    self.insert(KeyHash::with::<Hasher>(hashed_id), chain)?,
                ))
            }
        }
    }

    fn insert(&mut self, key: KeyHash, value: Hashchain) -> Result<InsertProof> {
        let serialized_value = Self::serialize_value(&value)?;

        let old_root = self.get_current_root()?;
        let (old_value, non_membership_merkle_proof) = self.jmt.get_with_proof(key, self.epoch)?;

        let non_membership_proof = NonMembershipProof {
            root: old_root.into(),
            proof: non_membership_merkle_proof,
            key,
        };

        if old_value.is_some() {
            bail!("Key already exists");
        }

        // the update proof just contains another nm proof
        let (new_root, _, tree_update_batch) = self
            .jmt
            .put_value_set_with_proof(vec![(key, Some(serialized_value))], self.epoch + 1)?;
        self.queue_batch(tree_update_batch);
        self.write_batch()?;

        let (_, membership_proof) = self.jmt.get_with_proof(key, self.epoch)?;

        Ok(InsertProof {
            new_root: new_root.into(),
            value,
            non_membership_proof,
            membership_proof,
        })
    }

    fn update(&mut self, key: KeyHash, value: Hashchain) -> Result<UpdateProof> {
        let serialized_value = Self::serialize_value(&value)?;

        let old_root = self.get_current_root()?;
        let (old_value, _) = self.jmt.get_with_proof(key, self.epoch)?;

        if old_value.is_none() {
            bail!("Key does not exist");
        }

        let (new_root, proof, tree_update_batch) = self.jmt.put_value_set_with_proof(
            vec![(key, Some(serialized_value.clone()))],
            self.epoch + 1,
        )?;
        self.queue_batch(tree_update_batch);
        self.write_batch()?;

        Ok(UpdateProof {
            old_root,
            new_root,
            key,
            new_value: value,
            proof,
        })
    }

    fn get(&self, key: KeyHash) -> Result<Result<Hashchain, NonMembershipProof>> {
        let (value, proof) = self.jmt.get_with_proof(key, self.epoch)?;

        match value {
            Some(serialized_value) => {
                let deserialized_value = Self::deserialize_value(&serialized_value)?;
                Ok(Ok(deserialized_value))
            }
            None => Ok(Err(NonMembershipProof {
                root: self.get_current_root()?.into(),
                proof,
                key,
            })),
        }
    }
}

#[cfg(all(test, feature = "test_utils"))]
mod tests {
    use super::*;
    use crate::test_utils::TestTreeState;

    #[test]
    fn test_insert_and_get() {
        let mut tree_state = TestTreeState::default();
        let account = tree_state.create_account("key_1".to_string());

        let insert_proof = tree_state.insert_account(account.clone()).unwrap();
        assert!(insert_proof.verify().is_ok());

        let get_result = tree_state.tree.get(account.key_hash).unwrap().unwrap();
        assert_eq!(get_result, account.hashchain);
    }

    #[test]
    fn test_insert_duplicate_key() {
        let mut tree_state = TestTreeState::default();
        let account = tree_state.create_account("key_1".to_string());

        tree_state.insert_account(account.clone()).unwrap();

        let result = tree_state.insert_account(account.clone());
        assert!(result.is_err());
    }

    #[test]
    fn test_update_existing_key() {
        let mut tree_state = TestTreeState::default();

        let mut account = tree_state.create_account("key_1".to_string());
        tree_state.insert_account(account.clone()).unwrap();

        // Add a new key
        tree_state.add_key_to_account(&mut account).unwrap();

        // Update the account using the correct key index
        let update_proof = tree_state.update_account(account.clone()).unwrap();
        assert!(update_proof.verify().is_ok());

        let get_result = tree_state.tree.get(account.key_hash).unwrap().unwrap();
        assert_eq!(get_result, account.hashchain);
    }

    #[test]
    fn test_update_non_existing_key() {
        let mut tree_state = TestTreeState::default();
        let account = tree_state.create_account("key_1".to_string());

        let result = tree_state.update_account(account);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_non_existing_key() {
        let tree_state = TestTreeState::default();
        let key = KeyHash::with::<Hasher>(b"non_existing_key");

        let result = tree_state.tree.get(key).unwrap();
        assert!(result.is_err());

        if let Err(non_membership_proof) = result {
            assert!(non_membership_proof.verify().is_ok());
        }
    }

    #[test]
    fn test_multiple_inserts_and_updates() {
        let mut tree_state = TestTreeState::default();

        let mut account1 = tree_state.create_account("key_1".to_string());
        let mut account2 = tree_state.create_account("key_2".to_string());

        tree_state.insert_account(account1.clone()).unwrap();
        tree_state.insert_account(account2.clone()).unwrap();

        tree_state.add_key_to_account(&mut account1).unwrap();
        tree_state.add_key_to_account(&mut account2).unwrap();

        // Update accounts using the correct key indices
        tree_state.update_account(account1.clone()).unwrap();
        tree_state.update_account(account2.clone()).unwrap();

        let tree_hashchain1 = tree_state.tree.get(account1.key_hash).unwrap().unwrap();
        let tree_hashchain2 = tree_state.tree.get(account2.key_hash).unwrap().unwrap();

        assert_eq!(tree_hashchain1, account1.hashchain);
        assert_eq!(tree_hashchain2, account2.hashchain);
    }

    #[test]
    fn test_interleaved_inserts_and_updates() {
        let mut test_tree = TestTreeState::default();

        let mut account_1 = test_tree.create_account("key_1".to_string());
        let mut account_2 = test_tree.create_account("key_2".to_string());

        test_tree.insert_account(account_1.clone()).unwrap();

        test_tree.add_key_to_account(&mut account_1).unwrap();
        // Update account_1 using the correct key index
        test_tree.update_account(account_1.clone()).unwrap();

        test_tree.insert_account(account_2.clone()).unwrap();

        test_tree.add_key_to_account(&mut account_2).unwrap();

        // Update account_2 using the correct key index
        let last_proof = test_tree.update_account(account_2.clone()).unwrap();

        assert_eq!(
            test_tree.tree.get(account_1.key_hash).unwrap().unwrap(),
            account_1.hashchain
        );
        assert_eq!(
            test_tree.tree.get(account_2.key_hash).unwrap().unwrap(),
            account_2.hashchain
        );
        assert_eq!(
            last_proof.new_root,
            test_tree.tree.get_current_root().unwrap()
        );
    }

    #[test]
    fn test_root_hash_changes() {
        let mut tree_state = TestTreeState::default();
        let account = tree_state.create_account("key_1".to_string());

        let root_before = tree_state.tree.get_current_root().unwrap();
        tree_state
            .tree
            .insert(account.key_hash, account.hashchain)
            .unwrap();
        let root_after = tree_state.tree.get_current_root().unwrap();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_batch_writing() {
        let mut tree_state = TestTreeState::default();
        let account1 = tree_state.create_account("key_1".to_string());
        let account2 = tree_state.create_account("key_2".to_string());

        println!("Inserting key1: {:?}", account1.key_hash);
        tree_state.insert_account(account1.clone()).unwrap();

        println!(
            "Tree state after first insert: {:?}",
            tree_state.tree.get_commitment()
        );
        println!(
            "Tree state after first write_batch: {:?}",
            tree_state.tree.get_commitment()
        );

        // Try to get the first value immediately
        let get_result1 = tree_state.tree.get(account1.key_hash);
        println!("Get result for key1 after first write: {:?}", get_result1);

        println!("Inserting key2: {:?}", account2.key_hash);
        tree_state.insert_account(account2.clone()).unwrap();

        println!(
            "Tree state after second insert: {:?}",
            tree_state.tree.get_commitment()
        );
        println!(
            "Tree state after second write_batch: {:?}",
            tree_state.tree.get_commitment()
        );

        // Try to get both values
        let get_result1 = tree_state.tree.get(account1.key_hash);
        let get_result2 = tree_state.tree.get(account2.key_hash);

        println!("Final get result for key1: {:?}", get_result1);
        println!("Final get result for key2: {:?}", get_result2);

        assert_eq!(get_result1.unwrap().unwrap(), account1.hashchain);
        assert_eq!(get_result2.unwrap().unwrap(), account2.hashchain);
    }
}
