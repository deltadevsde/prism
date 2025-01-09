use anyhow::Result;
use jmt::{
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
    KeyHash, OwnedValue, Version,
};
use prism_common::digest::Digest;
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
    current_epoch: Arc<Mutex<u64>>,
    sync_height: Arc<Mutex<u64>>,
}

impl InMemoryDatabase {
    pub fn new() -> Self {
        InMemoryDatabase {
            nodes: Arc::new(Mutex::new(HashMap::new())),
            values: Arc::new(Mutex::new(HashMap::new())),
            commitments: Arc::new(Mutex::new(HashMap::new())),
            current_epoch: Arc::new(Mutex::new(0)),
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
        let nodes = self.nodes.lock().unwrap();
        nodes
            .iter()
            .filter_map(|(key, node)| {
                if let Node::Leaf(leaf) = node {
                    Some((key.clone(), leaf.clone()))
                } else {
                    None
                }
            })
            .max_by_key(|(_, leaf)| leaf.key_hash())
            .map(|(key, leaf)| Ok((key, leaf)))
            .transpose()
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

    fn get_epoch(&self) -> Result<u64> {
        Ok(*self.current_epoch.lock().unwrap())
    }

    fn set_epoch(&self, epoch: &u64) -> Result<()> {
        *self.current_epoch.lock().unwrap() = *epoch;
        Ok(())
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
        *self.current_epoch.lock().unwrap() = 0;
        Ok(())
    }
}
