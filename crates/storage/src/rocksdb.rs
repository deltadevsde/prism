use crate::Database;
use anyhow::Result;
use jmt::{
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
    KeyHash, OwnedValue, Version,
};
use prism_common::tree::Digest;
use prism_errors::DatabaseError;
use rocksdb::{DBWithThreadMode, MultiThreaded, Options, DB};

type RocksDB = DBWithThreadMode<MultiThreaded>;

pub struct RocksDBConnection {
    connection: RocksDB,
    path: String,
}

impl RocksDBConnection {
    pub fn new(path: &str) -> Result<RocksDBConnection> {
        let db = DB::open_default(path)?;

        Ok(Self {
            connection: db,
            path: path.to_string(),
        })
    }
}

impl Database for RocksDBConnection {
    fn get_commitment(&self, epoch: &u64) -> anyhow::Result<Digest> {
        let key = format!("commitments:epoch_{}", epoch);
        let raw_bytes = self.connection.get(key.as_bytes())?.ok_or_else(|| {
            DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch))
        })?;

        let value: [u8; 32] = raw_bytes
            .try_into()
            .expect("commitment digest should always be 32 bytes");

        Ok(Digest(value))
    }

    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> anyhow::Result<()> {
        Ok(self.connection.put::<&[u8], [u8; 32]>(
            format!("commitments:epoch_{}", epoch).as_bytes(),
            commitment.0,
        )?)
    }

    fn get_last_synced_height(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(b"app_state:sync_height")?
            .ok_or_else(|| DatabaseError::NotFoundError("current sync height".to_string()))?;

        Ok(u64::from_be_bytes(res.try_into().unwrap()))
    }

    fn set_last_synced_height(&self, height: &u64) -> anyhow::Result<()> {
        Ok(self
            .connection
            .put(b"app_state:sync_height", height.to_be_bytes())?)
    }

    fn get_epoch(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(b"app_state:epoch")?
            .ok_or_else(|| DatabaseError::NotFoundError("current epoch".to_string()))?;

        Ok(u64::from_be_bytes(res.try_into().unwrap()))
    }

    fn set_epoch(&self, epoch: &u64) -> anyhow::Result<()> {
        Ok(self
            .connection
            .put(b"app_state:epoch", epoch.to_be_bytes())?)
    }

    fn flush_database(&self) -> Result<()> {
        Ok(DB::destroy(&Options::default(), &self.path)?)
    }
}

impl TreeWriter for RocksDBConnection {
    fn write_node_batch(&self, _node_batch: &NodeBatch) -> Result<()> {
        todo!()
    }
}

impl TreeReader for RocksDBConnection {
    fn get_node_option(&self, _node_key: &NodeKey) -> Result<Option<Node>> {
        todo!()
    }

    fn get_value_option(
        &self,
        _max_version: Version,
        _key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        todo!()
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_common::tree::Digest;
    use tempfile::TempDir;

    #[test]
    fn test_get_commitment() {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDBConnection::new(temp_dir.path().to_str().unwrap()).unwrap();

        let epoch = 1;
        let commitment = Digest::from([0u8; 32]);
        db.set_commitment(&epoch, &commitment).unwrap();

        let result = db.get_commitment(&epoch).unwrap();
        assert_eq!(result, commitment);
    }

    #[test]
    fn test_set_commitment() {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDBConnection::new(temp_dir.path().to_str().unwrap()).unwrap();

        let epoch = 1;
        let commitment = Digest::from([0u8; 32]);
        db.set_commitment(&epoch, &commitment).unwrap();

        let result = db.get_commitment(&epoch).unwrap();
        assert_eq!(result, commitment);
    }

    #[test]
    fn test_get_epoch() {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDBConnection::new(temp_dir.path().to_str().unwrap()).unwrap();

        let epoch = 1;
        db.set_epoch(&epoch).unwrap();

        let result = db.get_epoch().unwrap();
        assert_eq!(result, epoch);
    }

    #[test]
    fn test_set_epoch() {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDBConnection::new(temp_dir.path().to_str().unwrap()).unwrap();

        let epoch = 1;
        db.set_epoch(&epoch).unwrap();

        let result = db.get_epoch().unwrap();
        assert_eq!(result, epoch);
    }
}
