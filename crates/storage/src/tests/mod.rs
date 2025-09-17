use serde::{Deserialize, Serialize};
use tempfile::TempDir;

#[cfg(feature = "rocksdb")]
use crate::rocksdb::*;
use crate::{Database, inmemory::InMemoryDatabase, sled::*};
use jmt::{
    KeyHash, OwnedValue, Version,
    storage::{NodeBatch, TreeReader, TreeWriter},
};
use prism_common::digest::Digest;
use prism_da::SuccinctProof;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum StorageBackend {
    #[cfg(feature = "rocksdb")]
    RocksDB(crate::rocksdb::RocksDBConfig),
    InMemory,
    Sled(crate::sled::SledConfig),
}

fn setup_db(backend: StorageBackend) -> Box<dyn Database> {
    match backend {
        #[cfg(feature = "rocksdb")]
        StorageBackend::RocksDB(cfg) => Box::new(RocksDBConnection::new(&cfg).unwrap()),
        StorageBackend::Sled(cfg) => Box::new(SledConnection::new(&cfg).unwrap()),
        StorageBackend::InMemory => Box::new(InMemoryDatabase::new()),
    }
}

fn test_rw_commitment(backend: StorageBackend) {
    let db = setup_db(backend);

    let epoch = 1;
    let commitment = Digest([1; 32]);

    db.set_commitment(&epoch, &commitment).unwrap();
    let read_commitment = db.get_commitment(&epoch).unwrap();

    assert_eq!(read_commitment, commitment);
}

fn test_write_and_read_value(backend: StorageBackend) {
    let db = setup_db(backend);

    let key_hash = KeyHash([1; 32]);
    let value: OwnedValue = vec![4, 5, 6];
    let version: Version = 1;

    let mut batch = NodeBatch::default();
    batch.insert_value(version, key_hash, value.clone());

    db.write_node_batch(&batch).unwrap();

    let read_value = db.get_value_option(version, key_hash).unwrap();
    assert_eq!(read_value, Some(value));
}

fn test_get_value_option_with_multiple_versions(backend: StorageBackend) {
    let db = setup_db(backend);

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

fn test_sync_height(backend: StorageBackend) {
    let db = setup_db(backend);

    let height = 12345u64;
    db.set_last_synced_height(&height).unwrap();
    let read_height = db.get_last_synced_height().unwrap();

    assert_eq!(read_height, height);
}

fn test_transaction_consistency(backend: StorageBackend) {
    let db = setup_db(backend);

    let key_hash = KeyHash([3; 32]);
    let value1: OwnedValue = vec![1, 2, 3];
    let value2: OwnedValue = vec![4, 5, 6];

    // Write two values in a single batch - should be atomic
    let mut batch = NodeBatch::default();
    batch.insert_value(1, key_hash, value1.clone());
    batch.insert_value(2, key_hash, value2.clone());

    db.write_node_batch(&batch).unwrap();

    // Both values should be retrievable
    assert_eq!(db.get_value_option(1, key_hash).unwrap(), Some(value1));
    assert_eq!(db.get_value_option(2, key_hash).unwrap(), Some(value2));
}

fn test_epoch_operations(backend: StorageBackend) {
    let db = setup_db(backend);

    // Test that getting latest epoch height fails when no epochs exist
    assert!(db.get_latest_epoch_height().is_err());

    let epoch = prism_da::FinalizedEpoch {
        height: 0,
        tip_da_height: 1,
        prev_commitment: Digest::hash("a"),
        current_commitment: Digest::hash("b"),
        snark: SuccinctProof::default(),
        stark: SuccinctProof::default(),
        signature: None,
    };

    db.add_epoch(&epoch).unwrap();

    let latest_height = db.get_latest_epoch_height().unwrap();
    assert_eq!(latest_height, 0);

    let retrieved_epoch = db.get_epoch(&0).unwrap();
    assert_eq!(retrieved_epoch.height, 0);
}

fn test_range_iteration(backend: StorageBackend) {
    let db = setup_db(backend);

    let key_hash = KeyHash([4; 32]);

    // Insert multiple versions
    for i in 0..10 {
        let mut batch = NodeBatch::default();
        let value: OwnedValue = vec![i as u8; 10];
        batch.insert_value(i, key_hash, value);
        db.write_node_batch(&batch).unwrap();
    }

    // Test getting values at different max versions
    for max_version in 0..10 {
        let result = db.get_value_option(max_version, key_hash).unwrap();
        assert!(result.is_some());
        let value = result.unwrap();
        assert_eq!(value[0], max_version as u8);
    }
}

macro_rules! generate_storage_tests {
    ($test_fn:ident) => {
        paste::paste! {
            #[test]
            fn [<$test_fn _sled>]() {
                let temp_dir = TempDir::new().unwrap();
                let db_path = temp_dir.path().join("test_sled");
                let cfg = SledConfig::new(db_path.to_str().unwrap());
                $test_fn(StorageBackend::Sled(cfg));
            }

            #[test]
            fn [<$test_fn _inmemory>]() {
                $test_fn(StorageBackend::InMemory);
            }

            #[cfg(feature = "rocksdb")]
            #[test]
            fn [<$test_fn _rocksdb>]() {
                let temp_dir = TempDir::new().unwrap();
                let cfg = RocksDBConfig::new(temp_dir.path().to_str().unwrap());
                $test_fn(StorageBackend::RocksDB(cfg));
            }
        }
    };
}

generate_storage_tests!(test_rw_commitment);
generate_storage_tests!(test_write_and_read_value);
generate_storage_tests!(test_get_value_option_with_multiple_versions);
generate_storage_tests!(test_sync_height);
generate_storage_tests!(test_transaction_consistency);
generate_storage_tests!(test_epoch_operations);
generate_storage_tests!(test_range_iteration);
