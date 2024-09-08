use anyhow::{anyhow, bail, ensure, Context, Result};
use bls12_381::Scalar;
use borsh::{from_slice, to_vec, BorshDeserialize, BorshSerialize};
use jmt::{
    proof::{SparseMerkleProof, UpdateMerkleProof},
    storage::{NodeBatch, TreeReader, TreeUpdateBatch, TreeWriter},
    JellyfishMerkleTree, KeyHash, RootHash, Sha256Jmt, SimpleHasher,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::common::Hashchain;

pub const SPARSE_MERKLE_PLACEHOLDER_HASH: Digest =
    Digest::new(*b"SPARSE_MERKLE_PLACEHOLDER_HASH__");

pub type Hasher = sha2::Sha256;

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Copy,
)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn to_bytes(&self) -> [u8; 32] {
        return self.0;
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

impl Into<RootHash> for Digest {
    fn into(self) -> RootHash {
        RootHash::from(self.0)
    }
}

impl Into<Digest> for RootHash {
    fn into(self) -> Digest {
        Digest(self.0)
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

pub fn hash(data: &[u8]) -> Digest {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    Digest(hasher.finalize())
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum Proof {
    Update(UpdateProof),
    Insert(InsertProof),
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
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

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
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
            .context("Invalid NonMembershipProof");

        let value = to_vec(&self.value).unwrap();

        self.membership_proof.clone().verify_existence(
            self.new_root.into(),
            self.non_membership_proof.key,
            value,
        );

        Ok(())
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct UpdateProof {
    pub old_root: RootHash,
    pub new_root: RootHash,

    pub key: KeyHash,
    pub new_value: Hashchain,

    pub proof: UpdateMerkleProof<Hasher>,
}

impl UpdateProof {
    pub fn verify(&self) -> Result<()> {
        let new_value = to_vec(&self.new_value).unwrap();

        self.proof.clone().verify_update(
            self.old_root,
            self.new_root,
            vec![(self.key, Some(new_value))],
        )
    }
}

pub trait SnarkableTree {
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
            jmt: Sha256Jmt::new(store),
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

    fn get_current_root(&self) -> Result<RootHash> {
        self.jmt
            .get_root_hash(self.epoch)
            .map_err(|e| anyhow!("Failed to get root hash: {}", e))
    }

    fn serialize_value(value: &Hashchain) -> Result<Vec<u8>> {
        to_vec(value).map_err(|e| anyhow!("Failed to serialize value: {}", e))
    }

    fn deserialize_value(bytes: &[u8]) -> Result<Hashchain> {
        from_slice::<Hashchain>(bytes).map_err(|e| anyhow!("Failed to deserialize value: {}", e))
    }
}

impl<S> SnarkableTree for KeyDirectoryTree<S>
where
    S: TreeReader + TreeWriter,
{
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

#[cfg(test)]
mod tests {
    use super::*;
    use jmt::mock::MockTreeStore;

    #[test]
    fn test_insert_and_get() {
        let store = Arc::new(MockTreeStore::default());
        let mut tree = KeyDirectoryTree::new(store.clone());

        let hc1 = Hashchain::new("key_1".into());
        let key = hc1.get_keyhash();

        println!("hc1: {:?}", hc1);
        println!("key: {:?}", key);

        println!("Initial tree state: {:?}", tree.get_commitment());

        let insert_proof = tree.insert(key, hc1.clone());
        assert!(insert_proof.is_ok());

        println!("After first insert: {:?}", tree.get_commitment());

        let get_result = tree.get(key).unwrap().unwrap();

        assert_eq!(get_result, hc1);
    }

    #[test]
    fn test_insert_duplicate_key() {
        let store = Arc::new(MockTreeStore::default());
        let mut tree = KeyDirectoryTree::new(store);

        let hc1 = Hashchain::new("key_1".into());
        let key = hc1.get_keyhash();

        tree.insert(key, hc1.clone()).unwrap();

        let hc2 = Hashchain::new("key_1".into());
        let result = tree.insert(key, hc2);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_existing_key() {
        let store = Arc::new(MockTreeStore::default());
        let mut tree = KeyDirectoryTree::new(store);

        let mut hc1 = Hashchain::new("key_1".into());
        let key = hc1.get_keyhash();

        tree.insert(key, hc1.clone()).unwrap();

        hc1.add("new_value".into()).unwrap();
        let update_proof = tree.update(key, hc1.clone()).unwrap();
        assert!(update_proof.verify().is_ok());

        let get_result = tree.get(key).unwrap().unwrap();
        assert_eq!(get_result, hc1);
    }

    #[test]
    fn test_update_non_existing_key() {
        let store = Arc::new(MockTreeStore::default());
        let mut tree = KeyDirectoryTree::new(store);

        let hc1 = Hashchain::new("key_1".into());
        let key = hc1.get_keyhash();

        let result = tree.update(key, hc1);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_non_existing_key() {
        let store = MockTreeStore::default();
        let tree = KeyDirectoryTree::new(Arc::new(store));

        let key = KeyHash::with::<Hasher>(b"non_existing_key");
        let result = tree.get(key).unwrap();
        assert!(result.is_err());

        if let Err(non_membership_proof) = result {
            assert!(non_membership_proof.verify().is_ok());
        }
    }

    #[test]
    fn test_multiple_inserts_and_updates() {
        let store = MockTreeStore::default();
        let mut tree = KeyDirectoryTree::new(Arc::new(store));

        let mut hc1 = Hashchain::new("key_1".into());
        let mut hc2 = Hashchain::new("key_2".into());
        let key1 = hc1.get_keyhash();
        let key2 = hc2.get_keyhash();

        tree.insert(key1, hc1.clone()).unwrap();
        tree.insert(key2, hc2.clone()).unwrap();

        hc1.add("value1".into()).unwrap();
        hc2.add("value2".into()).unwrap();

        tree.update(key1, hc1.clone()).unwrap();
        tree.update(key2, hc2.clone()).unwrap();

        assert_eq!(tree.get(key1).unwrap().unwrap(), hc1);
        assert_eq!(tree.get(key2).unwrap().unwrap(), hc2);
    }

    #[test]
    fn test_interleaved_inserts_and_updates() {
        let store = MockTreeStore::default();
        let mut tree = KeyDirectoryTree::new(Arc::new(store));

        let mut hc1 = Hashchain::new("key_1".into());
        let mut hc2 = Hashchain::new("key_2".into());
        let key1 = hc1.get_keyhash();
        let key2 = hc2.get_keyhash();

        tree.insert(key1, hc1.clone()).unwrap();

        hc1.add("value1".into()).unwrap();
        tree.update(key1, hc1.clone()).unwrap();

        tree.insert(key2, hc2.clone()).unwrap();

        hc2.add("value2".into()).unwrap();
        let last_proof = tree.update(key2, hc2.clone()).unwrap();

        assert_eq!(tree.get(key1).unwrap().unwrap(), hc1);
        assert_eq!(tree.get(key2).unwrap().unwrap(), hc2);
        assert_eq!(last_proof.new_root, tree.get_current_root().unwrap());
    }

    #[test]
    fn test_root_hash_changes() {
        let store = Arc::new(MockTreeStore::default());
        let mut tree = KeyDirectoryTree::new(store);

        let hc1 = Hashchain::new("key_1".into());
        let key1 = hc1.get_keyhash();

        let root_before = tree.get_current_root().unwrap();
        tree.insert(key1, hc1).unwrap();
        let root_after = tree.get_current_root().unwrap();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_batch_writing() {
        let store = Arc::new(MockTreeStore::default());
        let mut tree = KeyDirectoryTree::new(store.clone());

        let hc1 = Hashchain::new("key_1".into());
        let key1 = hc1.get_keyhash();

        println!("Inserting key1: {:?}", key1);
        tree.insert(key1, hc1.clone()).unwrap();

        println!("Tree state after first insert: {:?}", tree.get_commitment());
        println!(
            "Tree state after first write_batch: {:?}",
            tree.get_commitment()
        );

        // Try to get the first value immediately
        let get_result1 = tree.get(key1);
        println!("Get result for key1 after first write: {:?}", get_result1);

        let hc2 = Hashchain::new("key_2".into());
        let key2 = hc2.get_keyhash();

        println!("Inserting key2: {:?}", key2);
        tree.insert(key2, hc2.clone()).unwrap();

        println!(
            "Tree state after second insert: {:?}",
            tree.get_commitment()
        );
        println!(
            "Tree state after second write_batch: {:?}",
            tree.get_commitment()
        );

        // Try to get both values
        let get_result1 = tree.get(key1);
        let get_result2 = tree.get(key2);

        println!("Final get result for key1: {:?}", get_result1);
        println!("Final get result for key2: {:?}", get_result2);

        assert_eq!(get_result1.unwrap().unwrap(), hc1);
        assert_eq!(get_result2.unwrap().unwrap(), hc2);
    }
}
