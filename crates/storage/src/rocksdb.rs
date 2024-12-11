use std::sync::Arc;

use crate::Database;
use anyhow::{anyhow, Result};
use jmt::{
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
    KeyHash, OwnedValue, Version,
};
use prism_common::digest::Digest;
use prism_errors::DatabaseError;
use prism_serde::{
    binary::{FromBinary, ToBinary},
    hex::{FromHex, ToHex},
};
use rocksdb::{DBWithThreadMode, MultiThreaded, Options, DB};

const KEY_PREFIX_COMMITMENTS: &str = "commitments:epoch_";
const KEY_PREFIX_NODE: &str = "node:";
const KEY_PREFIX_VALUE_HISTORY: &str = "value_history:";

type RocksDB = DBWithThreadMode<MultiThreaded>;

#[derive(Clone)]
pub struct RocksDBConnection {
    connection: Arc<RocksDB>,
    path: String,
}

impl RocksDBConnection {
    pub fn new(path: &str) -> Result<RocksDBConnection> {
        let db = DB::open_default(path)?;

        Ok(Self {
            connection: Arc::new(db),
            path: path.to_string(),
        })
    }
}

impl Database for RocksDBConnection {
    fn get_commitment(&self, epoch: &u64) -> anyhow::Result<Digest> {
        let key = format!("{KEY_PREFIX_COMMITMENTS}{}", epoch);
        let raw_bytes = self.connection.get(key.as_bytes())?.ok_or_else(|| {
            DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch))
        })?;

        let value: [u8; 32] =
            raw_bytes.try_into().expect("commitment digest should always be 32 bytes");

        Ok(Digest(value))
    }

    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> anyhow::Result<()> {
        Ok(self.connection.put::<&[u8], [u8; 32]>(
            format!("{KEY_PREFIX_COMMITMENTS}{}", epoch).as_bytes(),
            commitment.0,
        )?)
    }

    fn get_last_synced_height(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(b"app_state:sync_height")?
            .ok_or_else(|| DatabaseError::NotFoundError("current sync height".to_string()))?;

        Ok(u64::from_be_bytes(res.try_into().map_err(|e| {
            anyhow!("failed byte conversion from BigEndian to u64: {:?}", e)
        })?))
    }

    fn set_last_synced_height(&self, height: &u64) -> anyhow::Result<()> {
        Ok(self.connection.put(b"app_state:sync_height", height.to_be_bytes())?)
    }

    fn get_epoch(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(b"app_state:epoch")?
            .ok_or_else(|| DatabaseError::NotFoundError("current epoch".to_string()))?;

        Ok(u64::from_be_bytes(res.try_into().map_err(|e| {
            anyhow!("failed byte conversion from BigEndian to u64: {:?}", e)
        })?))
    }

    fn set_epoch(&self, epoch: &u64) -> anyhow::Result<()> {
        Ok(self.connection.put(b"app_state:epoch", epoch.to_be_bytes())?)
    }

    fn flush_database(&self) -> Result<()> {
        Ok(DB::destroy(&Options::default(), &self.path)?)
    }
}

impl TreeReader for RocksDBConnection {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let key = format!("{KEY_PREFIX_NODE}{}", node_key.encode_to_bytes()?.to_hex());
        let value = self.connection.get(key.as_bytes())?;

        match value {
            Some(data) => Ok(Some(Node::decode_from_bytes(&data)?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let value_key = format!("{KEY_PREFIX_VALUE_HISTORY}{}", key_hash.0.to_hex());
        let iter = self.connection.prefix_iterator(value_key.as_bytes());

        let mut latest_value = None;
        let mut latest_version = 0;

        for item in iter {
            let (key, value) = item?;
            let version =
                Version::decode_from_bytes(&Vec::<u8>::from_hex(&key[value_key.len() + 1..])?)?;

            if version <= max_version && version > latest_version {
                latest_version = version;
                latest_value = Some(value);
            }
        }

        latest_value.map(|v| OwnedValue::decode_from_bytes(&v)).transpose()
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let mut iter = self.connection.iterator(rocksdb::IteratorMode::End);

        while let Some(Ok((key, value))) = iter.next() {
            if key.starts_with(KEY_PREFIX_NODE.as_bytes()) {
                let node: Node = Node::decode_from_bytes(&value)?;
                if let Node::Leaf(leaf) = node {
                    let node_key = NodeKey::decode_from_bytes(&Vec::<u8>::from_hex(
                        &key[KEY_PREFIX_NODE.len()..],
                    )?)?;
                    return Ok(Some((node_key, leaf)));
                }
            }
        }

        Ok(None)
    }
}

impl TreeWriter for RocksDBConnection {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();

        for (node_key, node) in node_batch.nodes() {
            let key = format!("{KEY_PREFIX_NODE}{}", node_key.encode_to_bytes()?.to_hex());
            let value = node.encode_to_bytes()?;
            batch.put(key.as_bytes(), &value);
        }

        for ((version, key_hash), value) in node_batch.values() {
            let value_key = format!("{KEY_PREFIX_VALUE_HISTORY}{}", key_hash.0.to_hex());
            let version_key = format!("{}:{}", value_key, version.encode_to_bytes()?.to_hex());

            if let Some(v) = value {
                let serialized_value = v.encode_to_bytes()?;
                batch.put(version_key.as_bytes(), &serialized_value);
            } else {
                batch.delete(version_key.as_bytes());
            }
        }

        self.connection.write(batch)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmt::{KeyHash, OwnedValue, Version};
    use tempfile::TempDir;

    fn setup_db() -> (TempDir, RocksDBConnection) {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDBConnection::new(temp_dir.path().to_str().unwrap()).unwrap();
        (temp_dir, db)
    }

    #[test]
    fn test_rw_commitment() {
        let (_temp_dir, db) = setup_db();

        let epoch = 1;
        let commitment = Digest([1; 32]);

        db.set_commitment(&epoch, &commitment).unwrap();
        let read_commitment = db.get_commitment(&epoch).unwrap();

        assert_eq!(read_commitment, commitment);
    }

    #[test]
    fn test_rw_epoch() {
        let (_temp_dir, db) = setup_db();

        let epoch = 1;

        db.set_epoch(&epoch).unwrap();
        let read_epoch = db.get_epoch().unwrap();

        assert_eq!(read_epoch, epoch);
    }

    #[test]
    fn test_write_and_read_value() {
        let (_temp_dir, db) = setup_db();

        let key_hash = KeyHash([1; 32]);
        let value: OwnedValue = vec![4, 5, 6];
        let version: Version = 1;

        let mut batch = NodeBatch::default();
        batch.insert_value(version, key_hash, value.clone());

        db.write_node_batch(&batch).unwrap();

        let read_value = db.get_value_option(version, key_hash).unwrap();
        assert_eq!(read_value, Some(value));
    }

    #[test]
    fn test_get_value_option_with_multiple_versions() {
        let (_temp_dir, db) = setup_db();

        let key_hash = KeyHash([2; 32]);
        let value1: OwnedValue = vec![1, 1, 1];
        let value2: OwnedValue = vec![2, 2, 2];

        let mut batch = NodeBatch::default();
        batch.insert_value(1, key_hash, value1.clone());
        batch.insert_value(2, key_hash, value2.clone());

        db.write_node_batch(&batch).unwrap();

        assert_eq!(db.get_value_option(1, key_hash).unwrap(), Some(value1));
        assert_eq!(
            db.get_value_option(2, key_hash).unwrap(),
            Some(value2.clone())
        );
        assert_eq!(db.get_value_option(3, key_hash).unwrap(), Some(value2));
    }
}
