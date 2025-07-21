use std::sync::Arc;

use crate::Database;
use anyhow::{Result, anyhow};
use jmt::{
    KeyHash, OwnedValue, Version,
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
};
use prism_common::digest::Digest;
use prism_errors::DatabaseError;
use prism_serde::binary::{FromBinary, ToBinary};
use serde::{Deserialize, Serialize};
use sled::{Db, Transactional, Tree};

const KEY_PREFIX_NODE: &str = "node:";
const KEY_PREFIX_VALUE_HISTORY: &str = "value_history:";

const KEY_PREFIX_EPOCHS: &str = "epochs:height_";
const KEY_PREFIX_COMMITMENTS: &str = "commitments:epoch_";

const KEY_SYNC_HEIGHT: &str = "app_state:sync_height";
const KEY_LATEST_EPOCH_HEIGHT: &str = "app_state:latest_epoch_height";

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct SledConfig {
    pub path: String,
    pub cache_capacity: Option<u64>,
    pub flush_every_ms: Option<u64>,
}

impl SledConfig {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            cache_capacity: None,
            flush_every_ms: None,
        }
    }

    const fn with_cache_capacity(mut self, capacity: u64) -> Self {
        self.cache_capacity = Some(capacity);
        self
    }

    const fn with_flush_every_ms(mut self, ms: u64) -> Self {
        self.flush_every_ms = Some(ms);
        self
    }
}

#[derive(Clone)]
pub struct SledConnection {
    connection: Arc<Db>,
    node_tree: Tree,
    value_tree: Tree,
    path: String,
}

impl SledConnection {
    pub fn new(cfg: &SledConfig) -> Result<SledConnection> {
        let mut config = sled::Config::new().path(&cfg.path);

        if let Some(capacity) = cfg.cache_capacity {
            config = config.cache_capacity(capacity);
        }

        if let Some(flush_ms) = cfg.flush_every_ms {
            config = config.flush_every_ms(Some(flush_ms));
        }

        let db = config.open()?;
        let node_tree = db.open_tree(KEY_PREFIX_NODE)?;
        let value_tree = db.open_tree(KEY_PREFIX_VALUE_HISTORY)?;

        Ok(Self {
            connection: Arc::new(db),
            node_tree,
            value_tree,
            path: cfg.path.clone(),
        })
    }
}

impl Database for SledConnection {
    fn get_commitment(&self, epoch: &u64) -> anyhow::Result<Digest> {
        let key = format!("{KEY_PREFIX_COMMITMENTS}{}", epoch);
        let raw_bytes = self.connection.get(key.as_bytes())?.ok_or_else(|| {
            DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch))
        })?;

        let value: [u8; 32] = raw_bytes.as_ref().try_into().map_err(|_| {
            anyhow!(
                "commitment digest should always be 32 bytes, got {} bytes",
                raw_bytes.len()
            )
        })?;

        Ok(Digest(value))
    }

    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> anyhow::Result<()> {
        let key = format!("{KEY_PREFIX_COMMITMENTS}{}", epoch);
        self.connection.insert(key.as_bytes(), &commitment.0[..])?;
        Ok(())
    }

    fn get_last_synced_height(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(KEY_SYNC_HEIGHT)?
            .ok_or_else(|| DatabaseError::NotFoundError("current sync height".to_string()))?;

        Ok(u64::from_be_bytes(res.as_ref().try_into().map_err(
            |_| {
                anyhow!(
                    "failed byte conversion from BigEndian to u64: expected 8 bytes, got {}",
                    res.len()
                )
            },
        )?))
    }

    fn set_last_synced_height(&self, height: &u64) -> anyhow::Result<()> {
        self.connection.insert(KEY_SYNC_HEIGHT, &height.to_be_bytes())?;
        Ok(())
    }

    fn get_epoch(&self, height: &u64) -> anyhow::Result<prism_da::FinalizedEpoch> {
        let key = format!("{}{}", KEY_PREFIX_EPOCHS, height);
        let epoch_data = self
            .connection
            .get(key.as_bytes())?
            .ok_or_else(|| DatabaseError::NotFoundError(format!("epoch at height {}", height)))?;

        prism_da::FinalizedEpoch::decode_from_bytes(epoch_data.as_ref()).map_err(|e| {
            anyhow!(DatabaseError::ParsingError(format!(
                "Failed to decode epoch at height {}: {}",
                height, e
            )))
        })
    }

    fn add_epoch(&self, epoch: &prism_da::FinalizedEpoch) -> anyhow::Result<()> {
        // Get the latest height to check for sequential ordering
        let latest_height = self.get_latest_epoch_height().ok();

        if let Some(latest) = latest_height {
            if latest as usize + 1 != epoch.height as usize {
                return Err(anyhow!(DatabaseError::WriteError(format!(
                    "epoch height mismatch: expected {}, got {}",
                    latest + 1,
                    epoch.height
                ))));
            }
        } else if epoch.height != 0 {
            // If there's no latest height, we expect the first epoch to have height 0
            return Err(anyhow!(DatabaseError::WriteError(format!(
                "first epoch must have height 0, got {}",
                epoch.height
            ))));
        }

        // Encode the epoch to bytes
        let epoch_data = epoch.encode_to_bytes().map_err(|e| {
            anyhow!(DatabaseError::ParsingError(format!(
                "Failed to encode epoch at height {}: {}",
                epoch.height, e
            )))
        })?;

        // Use a transaction to atomically store the epoch and update the latest height
        let epoch_key = format!("{}{}", KEY_PREFIX_EPOCHS, epoch.height);
        let height_bytes = epoch.height.to_be_bytes();

        self.connection
            .transaction(|tx| {
                tx.insert(epoch_key.as_bytes(), epoch_data.as_slice())?;
                tx.insert(KEY_LATEST_EPOCH_HEIGHT, &height_bytes)?;
                Ok::<(), sled::transaction::ConflictableTransactionError<anyhow::Error>>(())
            })
            .unwrap();

        Ok(())
    }

    fn get_latest_epoch_height(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(KEY_LATEST_EPOCH_HEIGHT)?
            .ok_or_else(|| DatabaseError::NotFoundError("latest epoch height".to_string()))?;

        Ok(u64::from_be_bytes(res.as_ref().try_into().map_err(
            |_| {
                anyhow!(
                    "failed byte conversion from BigEndian to u64: expected 8 bytes, got {}",
                    res.len()
                )
            },
        )?))
    }

    fn get_latest_epoch(&self) -> anyhow::Result<prism_da::FinalizedEpoch> {
        let height = self.get_latest_epoch_height()?;
        self.get_epoch(&height)
    }

    fn flush_database(&self) -> Result<()> {
        // sled doesn't have a destroy method, so we need to drop the connection and remove the
        // directory
        drop(self.connection.clone());
        std::fs::remove_dir_all(&self.path)?;
        Ok(())
    }
}

impl TreeReader for SledConnection {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let value = self.node_tree.get(node_key.encode_to_bytes()?)?;

        match value {
            Some(data) => Ok(Some(Node::decode_from_bytes(data.as_ref())?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let value_key = key_hash.0;
        let max_version_bytes = max_version.to_be_bytes();
        let mut max_key = Vec::with_capacity(32 + max_version_bytes.len());
        max_key.extend_from_slice(&value_key);
        max_key.extend_from_slice(&max_version_bytes);

        // Use reverse iteration to find the highest version <= max_version
        let mut iter = self.value_tree.range(..=max_key).rev();

        while let Some(Ok((key, value))) = iter.next() {
            if key.starts_with(&value_key) {
                return Ok(Some(OwnedValue::decode_from_bytes(value.as_ref())?));
            }
        }

        Ok(None)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        unimplemented!("JMT Restoration from snapshot is unimplemented.");
    }
}

impl TreeWriter for SledConnection {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        (&self.node_tree, &self.value_tree)
            .transaction(|(tx_node, tx_values)| {
                for (node_key, node) in node_batch.nodes() {
                    let key = node_key.encode_to_bytes().unwrap();
                    let value = node.encode_to_bytes().unwrap();
                    tx_node.insert(key, value).unwrap();
                }

                for ((version, key_hash), value) in node_batch.values() {
                    let value_key = key_hash.0;
                    let encoded_value = value
                        .as_ref()
                        .map(|v| v.encode_to_bytes())
                        .transpose()
                        .unwrap()
                        .unwrap_or_default();
                    let version_bytes = version.to_be_bytes();

                    let mut fkey = Vec::with_capacity(32 + version_bytes.len());
                    fkey.extend_from_slice(&value_key);
                    fkey.extend_from_slice(&version_bytes);
                    tx_values.insert(fkey, encoded_value).unwrap();
                }

                Ok::<(), sled::transaction::ConflictableTransactionError<anyhow::Error>>(())
            })
            .unwrap();

        Ok(())
    }
}
