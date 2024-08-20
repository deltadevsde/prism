pub mod batch;
pub mod insert;
pub mod update;
pub mod utils;

#[cfg(test)]
mod tests {
    use crate::common::Hashchain;
    use crate::tree::{Hasher, KeyDirectoryTree, SnarkableTree};
    use jmt::mock::MockTreeStore;
    use jmt::KeyHash;
    use std::sync::Arc;

    #[test]
    fn test_key_directory_tree() {
        let store = Arc::new(MockTreeStore::default());
        let mut tree = KeyDirectoryTree::new(store);

        println!("Initial tree state: {:?}", tree.get_commitment());

        // Test insert
        let hc1 = Hashchain::new("key_1".into());
        let key1 = hc1.get_keyhash();
        let insert_proof = tree
            .insert(key1, hc1.clone())
            .expect("Insert should succeed");
        assert!(insert_proof.verify().is_ok());
        tree.write_batch().expect("Write batch should succeed");

        println!("After first insert: {:?}", tree.get_commitment());

        // Test get after insert
        // Test get after insert
        let get_result = tree.get(key1).expect("Get should succeed");
        println!("Get result after insert: {:?}", get_result);
        assert_eq!(get_result.expect("Key should exist"), hc1);

        // Test update
        let mut hc1_updated = hc1.clone();
        hc1_updated
            .add("new_value".into())
            .expect("Add to hashchain should succeed");
        let update_proof = tree
            .update(key1, hc1_updated.clone())
            .expect("Update should succeed");
        assert!(update_proof.verify().is_ok());
        tree.write_batch().expect("Write batch should succeed");

        // Test get after update
        let get_result_after_update = tree.get(key1).expect("Get should succeed");
        assert_eq!(
            get_result_after_update.expect("Key should exist"),
            hc1_updated
        );

        // Test insert duplicate key
        let insert_duplicate_result = tree.insert(key1, hc1.clone());
        assert!(insert_duplicate_result.is_err());

        // Test update non-existing key
        let non_existing_key = KeyHash::with::<Hasher>(b"non_existing_key");
        let update_non_existing_result = tree.update(non_existing_key, hc1.clone());
        assert!(update_non_existing_result.is_err());

        // Test get non-existing key
        let get_non_existing_result = tree.get(non_existing_key).expect("Get should not fail");
        assert!(get_non_existing_result.is_err());
        if let Err(non_membership_proof) = get_non_existing_result {
            assert!(non_membership_proof.verify().is_ok());
        }

        // Test multiple inserts and updates
        let hc2 = Hashchain::new("key_2".into());
        let key2 = hc2.get_keyhash();
        tree.insert(key2, hc2.clone())
            .expect("Insert should succeed");
        tree.write_batch().expect("Write batch should succeed");

        let mut hc2_updated = hc2.clone();
        hc2_updated
            .add("value2".into())
            .expect("Add to hashchain should succeed");
        tree.update(key2, hc2_updated.clone())
            .expect("Update should succeed");
        tree.write_batch().expect("Write batch should succeed");

        assert_eq!(tree.get(key2).unwrap().unwrap(), hc2_updated);

        // Test root hash changes
        let root_before = tree
            .get_commitment()
            .expect("Get commitment should succeed");
        let hc3 = Hashchain::new("key_3".into());
        let key3 = hc3.get_keyhash();
        tree.insert(key3, hc3).expect("Insert should succeed");
        tree.write_batch().expect("Write batch should succeed");
        let root_after = tree
            .get_commitment()
            .expect("Get commitment should succeed");

        assert_ne!(root_before, root_after);

        // Test batch writing
        let hc4 = Hashchain::new("key_4".into());
        let hc5 = Hashchain::new("key_5".into());
        let key4 = hc4.get_keyhash();
        let key5 = hc5.get_keyhash();

        tree.insert(key4, hc4.clone())
            .expect("Insert should succeed");
        tree.insert(key5, hc5.clone())
            .expect("Insert should succeed");

        // Before writing the batch
        assert!(tree.get(key4).unwrap().is_err());
        assert!(tree.get(key5).unwrap().is_err());

        tree.write_batch().expect("Write batch should succeed");

        // After writing the batch
        assert_eq!(tree.get(key4).unwrap().unwrap(), hc4);
        assert_eq!(tree.get(key5).unwrap().unwrap(), hc5);
    }
}
