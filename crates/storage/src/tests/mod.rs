use crate::rocksdb::*;
use tempfile::TempDir;

use crate::Database;
use jmt::{
    KeyHash, OwnedValue, Version,
    storage::{NodeBatch, TreeReader, TreeWriter},
};
use prism_common::digest::Digest;

fn setup_db() -> (TempDir, RocksDBConnection) {
    let temp_dir = TempDir::new().unwrap();
    let cfg = RocksDBConfig::new(temp_dir.path().to_str().unwrap());
    let db = RocksDBConnection::new(&cfg).unwrap();
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
