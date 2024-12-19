use anyhow::{anyhow, Result};
use jmt::{
    self,
    storage::{NodeBatch, TreeReader, TreeUpdateBatch, TreeWriter},
    JellyfishMerkleTree, KeyHash, RootHash,
};
use prism_common::digest::Digest;
use std::sync::Arc;

use crate::hasher::TreeHasher;

pub const SPARSE_MERKLE_PLACEHOLDER_HASH: KeyHash = KeyHash(*b"SPARSE_MERKLE_PLACEHOLDER_HASH__");

/// Wraps a [`JellyfishMerkleTree`] to provide a key-value store for [`Hashchain`]s with batched insertions.
/// This is prism's primary data structure for storing and retrieving [`Hashchain`]s.
pub struct KeyDirectoryTree<S>
where
    S: TreeReader + TreeWriter,
{
    pub(crate) jmt: JellyfishMerkleTree<Arc<S>, TreeHasher>,
    pub(crate) epoch: u64,
    pending_batch: Option<NodeBatch>,
    db: Arc<S>,
}

impl<S> KeyDirectoryTree<S>
where
    S: TreeReader + TreeWriter,
{
    pub fn new(store: Arc<S>) -> Self {
        let tree = Self {
            db: store.clone(),
            jmt: JellyfishMerkleTree::<Arc<S>, TreeHasher>::new(store),
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

    pub fn load(store: Arc<S>, epoch: u64) -> Self {
        if epoch == 0 {
            return KeyDirectoryTree::new(store);
        }
        Self {
            db: store.clone(),
            jmt: JellyfishMerkleTree::<Arc<S>, TreeHasher>::new(store),
            pending_batch: None,
            epoch,
        }
    }

    pub fn get_commitment(&self) -> Result<Digest> {
        let root = self.get_current_root()?;
        Ok(Digest(root.0))
    }

    pub(crate) fn queue_batch(&mut self, batch: TreeUpdateBatch) {
        match self.pending_batch {
            Some(ref mut pending_batch) => pending_batch.merge(batch.node_batch),
            None => self.pending_batch = Some(batch.node_batch),
        }
    }

    pub(crate) fn write_batch(&mut self) -> Result<()> {
        if let Some(batch) = self.pending_batch.take() {
            self.db.write_node_batch(&batch)?;
            self.epoch += 1;
        }
        Ok(())
    }

    pub fn get_current_root(&self) -> Result<RootHash> {
        self.jmt.get_root_hash(self.epoch).map_err(|e| anyhow!("Failed to get root hash: {}", e))
    }
}
