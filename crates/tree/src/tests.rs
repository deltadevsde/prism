use std::sync::Arc;

use jmt::{mock::MockTreeStore, KeyHash};
use prism_common::transaction_builder::TransactionBuilder;
use prism_keys::{SigningKey, KeyAlgorithm};

use crate::{
    hasher::TreeHasher, key_directory_tree::KeyDirectoryTree, proofs::Proof,
    snarkable_tree::SnarkableTree, HashchainResponse::*,
};

fn test_insert_and_get(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let Proof::Insert(insert_proof) = tree.process_transaction(service_tx).unwrap() else {
        panic!("Processing transaction did not return the expected insert proof");
    };
    assert!(insert_proof.verify().is_ok());

    let account_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();

    let Proof::Insert(insert_proof) = tree.process_transaction(account_tx).unwrap() else {
        panic!("Processing transaction did not return the expected insert proof");
    };
    assert!(insert_proof.verify().is_ok());

    let Found(hashchain, membership_proof) =
        tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap()
    else {
        panic!("Expected hashchain to be found, but was not found.")
    };

    let test_hashchain =
        tx_builder.get_hashchain("acc_1").expect("Getting builder hashchain should work");

    assert_eq!(&hashchain, test_hashchain);
    assert!(membership_proof.verify().is_ok());
}

fn test_insert_for_nonexistent_service_fails(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_signing_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create service signing key");

    let invalid_account_tx = tx_builder
        .create_account_with_random_key(
            algorithm,
            "acc_1",
            "service_id_that_does_not_exist",
            &service_signing_key,
        )
        .build();

    let insertion_result = tree.process_transaction(invalid_account_tx);
    assert!(insertion_result.is_err());
}

fn test_insert_with_invalid_service_challenge_fails(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();

    // The correct way was to use the key from service registration,
    // but here we want things to break
    let incorrect_service_signing_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create service signing key");

    let initial_acc_signing_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create account signing key");

    let acc_with_invalid_challenge_tx = tx_builder
        .create_account(
            "key_1",
            "service_1",
            &incorrect_service_signing_key,
            initial_acc_signing_key,
        )
        .build();

    let Proof::Insert(insert_proof) = tree.process_transaction(service_tx).unwrap() else {
        panic!("Processing service registration failed")
    };
    assert!(insert_proof.verify().is_ok());

    let create_account_result = tree.process_transaction(acc_with_invalid_challenge_tx);
    assert!(create_account_result.is_err());
}

fn test_insert_duplicate_key(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let account_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();
    let account_with_same_id_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").build();

    let Proof::Insert(insert_proof) = tree.process_transaction(service_tx).unwrap() else {
        panic!("Processing service registration failed")
    };
    assert!(insert_proof.verify().is_ok());

    let Proof::Insert(insert_proof) = tree.process_transaction(account_tx).unwrap() else {
        panic!("Processing Account creation failed")
    };
    assert!(insert_proof.verify().is_ok());

    let create_acc_with_same_id_result = tree.process_transaction(account_with_same_id_tx);
    assert!(create_acc_with_same_id_result.is_err());
}

fn test_update_existing_key(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let acc_tx = tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();

    tree.process_transaction(service_tx).unwrap();
    tree.process_transaction(acc_tx).unwrap();

    let key_tx = tx_builder.add_random_key_verified_with_root(algorithm, "acc_1").commit();

    let Proof::Update(update_proof) = tree.process_transaction(key_tx).unwrap() else {
        panic!("Processing key update failed")
    };
    assert!(update_proof.verify().is_ok());

    let get_result = tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap();
    let test_hashchain = tx_builder.get_hashchain("acc_1").unwrap();

    assert!(matches!(get_result, Found(hc, _) if &hc == test_hashchain));
}

fn test_update_non_existing_key(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();

    tree.process_transaction(service_tx).unwrap();

    // This is a signing key not known to the storage yet
    let random_signing_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create random signing key");
    // This transaction shall be invalid, because it is signed with an unknown key
    let invalid_key_tx = tx_builder.add_random_key(algorithm, "acc_1", &random_signing_key, 0).build();

    let result = tree.process_transaction(invalid_key_tx);
    assert!(result.is_err());
}

fn test_multiple_inserts_and_updates(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let acc1_tx = tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();
    let acc2_tx = tx_builder.create_account_with_random_key_signed(algorithm, "acc_2", "service_1").commit();

    tree.process_transaction(service_tx).unwrap();

    tree.process_transaction(acc1_tx).unwrap();
    tree.process_transaction(acc2_tx).unwrap();

    // Do insert and update accounts using the correct key indices
    let key_1_tx = tx_builder.add_random_key_verified_with_root(algorithm, "acc_1").commit();
    tree.process_transaction(key_1_tx).unwrap();

    let data_1_tx =
        tx_builder.add_unsigned_data_verified_with_root("acc_2", b"unsigned".to_vec()).commit();
    tree.process_transaction(data_1_tx).unwrap();

    let data_2_tx = tx_builder
        .add_randomly_signed_data_verified_with_root(algorithm, "acc_2", b"signed".to_vec())
        .commit();
    tree.process_transaction(data_2_tx).unwrap();

    let get_result1 = tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap();
    let get_result2 = tree.get(KeyHash::with::<TreeHasher>("acc_2")).unwrap();

    let test_hashchain_acc1 = tx_builder.get_hashchain("acc_1").unwrap();
    let test_hashchain_acc2 = tx_builder.get_hashchain("acc_2").unwrap();

    assert!(matches!(get_result1, Found(hc, _) if &hc == test_hashchain_acc1));
    assert!(matches!(get_result2, Found(hc, _) if &hc == test_hashchain_acc2));
}

fn test_interleaved_inserts_and_updates(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let acc1_tx = tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();
    let acc2_tx = tx_builder.create_account_with_random_key_signed(algorithm, "acc_2", "service_1").commit();

    tree.process_transaction(service_tx).unwrap();
    tree.process_transaction(acc1_tx).unwrap();

    let add_key_to_1_tx = tx_builder.add_random_key_verified_with_root(algorithm, "acc_1").commit();
    tree.process_transaction(add_key_to_1_tx).unwrap();

    tree.process_transaction(acc2_tx).unwrap();

    let add_key_to_2_tx = tx_builder.add_random_key_verified_with_root(algorithm, "acc_2").commit();
    let last_proof = tree.process_transaction(add_key_to_2_tx).unwrap();

    // Update account_2 using the correct key index
    let Proof::Update(update_proof) = last_proof else {
        panic!("Expetced insert proof for transaction");
    };

    let get_result1 = tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap();
    let get_result2 = tree.get(KeyHash::with::<TreeHasher>("acc_2")).unwrap();

    let test_hashchain_acc1 = tx_builder.get_hashchain("acc_1").unwrap();
    let test_hashchain_acc2 = tx_builder.get_hashchain("acc_2").unwrap();

    assert!(matches!(get_result1, Found(hc, _) if &hc == test_hashchain_acc1));
    assert!(matches!(get_result2, Found(hc, _) if &hc == test_hashchain_acc2));
    assert_eq!(update_proof.new_root, tree.get_commitment().unwrap());
}

fn test_root_hash_changes(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let account1_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();

    tree.process_transaction(service_tx).unwrap();

    let root_before = tree.get_current_root().unwrap();
    tree.process_transaction(account1_tx).unwrap();
    let root_after = tree.get_current_root().unwrap();

    assert_ne!(root_before, root_after);
}

fn test_batch_writing(algorithm: KeyAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let account1_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();
    let account2_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_2", "service_1").commit();

    tree.process_transaction(service_tx).unwrap();

    println!("Inserting acc_1");
    tree.process_transaction(account1_tx).unwrap();

    println!("Tree state after first insert: {:?}", tree.get_commitment());

    // Try to get the first value immediately
    let get_result1 = tree.get(KeyHash::with::<TreeHasher>("acc_1"));
    println!("Get result for key1 after first write: {:?}", get_result1);

    println!("Inserting acc_2");
    tree.process_transaction(account2_tx).unwrap();

    println!("Tree state after 2nd insert: {:?}", tree.get_commitment());

    // Try to get both values
    let get_result1 = tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap();
    let get_result2 = tree.get(KeyHash::with::<TreeHasher>("acc_2")).unwrap();

    println!("Final get result for key1: {:?}", get_result1);
    println!("Final get result for key2: {:?}", get_result2);

    let test_hashchain_acc1 = tx_builder.get_hashchain("acc_1").unwrap();
    let test_hashchain_acc2 = tx_builder.get_hashchain("acc_2").unwrap();

    assert!(matches!(get_result1, Found(hc, _) if &hc == test_hashchain_acc1));
    assert!(matches!(get_result2, Found(hc, _) if &hc == test_hashchain_acc2));
}

macro_rules! generate_algorithm_tests {
    ($test_fn:ident) => {
        paste::paste! {
            #[test]
            fn [<$test_fn _ed25519>]() {
                $test_fn(KeyAlgorithm::Ed25519);
            }

            #[test]
            fn [<$test_fn _secp256k1>]() {
                $test_fn(KeyAlgorithm::Secp256k1);
            }

            #[test]
            fn [<$test_fn _secp256r1>]() {
                $test_fn(KeyAlgorithm::Secp256r1);
            }
        }
    };
}

generate_algorithm_tests!(test_insert_and_get);
generate_algorithm_tests!(test_insert_for_nonexistent_service_fails);
generate_algorithm_tests!(test_insert_with_invalid_service_challenge_fails);
generate_algorithm_tests!(test_insert_duplicate_key);
generate_algorithm_tests!(test_update_existing_key);
generate_algorithm_tests!(test_update_non_existing_key);
generate_algorithm_tests!(test_multiple_inserts_and_updates);
generate_algorithm_tests!(test_interleaved_inserts_and_updates);
generate_algorithm_tests!(test_root_hash_changes);
generate_algorithm_tests!(test_batch_writing);

#[test]
fn test_get_non_existing_key() {
    let tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));

    let result = tree.get(KeyHash::with::<TreeHasher>("non_existing_id")).unwrap();

    let NotFound(non_membership_proof) = result else {
        panic!("Hashchain found for key while it was expected to be missing");
    };

    assert!(non_membership_proof.verify().is_ok());
}
