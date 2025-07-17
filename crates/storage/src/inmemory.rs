use anyhow::Result;
use jmt::{
    KeyHash, OwnedValue, Version,
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
};
use prism_common::digest::Digest;
use prism_da::FinalizedEpoch;
use prism_errors::DatabaseError;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::database::Database;

pub struct InMemoryDatabase {
    nodes: Arc<Mutex<HashMap<NodeKey, Node>>>,
    values: Arc<Mutex<HashMap<(Version, KeyHash), OwnedValue>>>,
    commitments: Arc<Mutex<HashMap<u64, Digest>>>,
    current_epochs: Arc<Mutex<Vec<FinalizedEpoch>>>,
    sync_height: Arc<Mutex<u64>>,
}

impl InMemoryDatabase {
    pub fn new() -> Self {
        InMemoryDatabase {
            nodes: Arc::new(Mutex::new(HashMap::new())),
            values: Arc::new(Mutex::new(HashMap::new())),
            commitments: Arc::new(Mutex::new(HashMap::new())),
            current_epochs: Arc::new(Mutex::new(Vec::new())),
            sync_height: Arc::new(Mutex::new(1)),
        }
    }
}

impl Default for InMemoryDatabase {
    fn default() -> Self {
        InMemoryDatabase::new()
    }
}

impl TreeReader for InMemoryDatabase {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self.nodes.lock().unwrap().get(node_key).cloned())
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        unimplemented!("JMT restoration from snapshot is unimplemented.")
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let values = self.values.lock().unwrap();
        Ok(values
            .iter()
            .filter(|((version, hash), _)| *version <= max_version && *hash == key_hash)
            .max_by_key(|((version, _), _)| *version)
            .map(|(_, value)| value.clone()))
    }
}

impl TreeWriter for InMemoryDatabase {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let mut nodes = self.nodes.lock().unwrap();
        let mut values = self.values.lock().unwrap();

        for (node_key, node) in node_batch.nodes() {
            nodes.insert(node_key.clone(), node.clone());
        }

        for ((version, key_hash), value) in node_batch.values() {
            values.insert((*version, *key_hash), value.clone().unwrap_or_default());
        }

        Ok(())
    }
}

impl Database for InMemoryDatabase {
    fn get_commitment(&self, epoch: &u64) -> Result<Digest> {
        self.commitments.lock().unwrap().get(epoch).cloned().ok_or_else(|| {
            DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch)).into()
        })
    }

    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> Result<()> {
        self.commitments.lock().unwrap().insert(*epoch, *commitment);
        Ok(())
    }

    fn get_epoch(&self, height: &u64) -> Result<FinalizedEpoch> {
        let epochs = self.current_epochs.lock().unwrap();
        match epochs.get(*height as usize) {
            Some(epoch) => Ok(epoch.clone()),
            None => Err(DatabaseError::NotFoundError(format!("epoch at height {}", height)).into()),
        }
    }

    fn add_epoch(&self, epoch: &FinalizedEpoch) -> Result<()> {
        let mut epochs = self.current_epochs.lock().unwrap();
        if epochs.len() != epoch.height as usize {
            return Err(DatabaseError::WriteError(format!(
                "epoch height mismatch: expected {}, got {}",
                epochs.len(),
                epoch.height
            ))
            .into());
        }
        epochs.push(epoch.clone());
        Ok(())
    }

    fn get_latest_epoch_height(&self) -> Result<u64> {
        let epochs = self.current_epochs.lock().unwrap();
        if epochs.is_empty() {
            return Err(DatabaseError::NotFoundError("epoch's latest height".to_string()).into());
        }
        Ok(epochs.len() as u64 - 1)
    }

    fn get_latest_epoch(&self) -> Result<FinalizedEpoch> {
        let height = self.get_latest_epoch_height()?;
        self.get_epoch(&height)
    }

    fn get_last_synced_height(&self) -> Result<u64> {
        Ok(*self.sync_height.lock().unwrap())
    }

    fn set_last_synced_height(&self, epoch: &u64) -> Result<()> {
        *self.sync_height.lock().unwrap() = *epoch;
        Ok(())
    }

    fn flush_database(&self) -> Result<()> {
        self.nodes.lock().unwrap().clear();
        self.values.lock().unwrap().clear();
        self.commitments.lock().unwrap().clear();
        self.current_epochs.lock().unwrap().clear();
        Ok(())
    }
}
