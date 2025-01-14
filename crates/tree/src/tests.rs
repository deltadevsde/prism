use std::sync::Arc;

use jmt::{mock::MockTreeStore, KeyHash};
use prism_common::{operation::SignatureBundle, transaction_builder::TransactionBuilder};
use prism_keys::{CryptoAlgorithm, SigningKey};

use crate::{
    hasher::TreeHasher, key_directory_tree::KeyDirectoryTree, proofs::Proof,
    snarkable_tree::SnarkableTree, AccountResponse::*,
};

fn test_insert_and_get(algorithm: CryptoAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let Proof::Insert(insert_proof) = tree.process_transaction(service_tx).unwrap() else {
        panic!("Processing transaction did not return the expected insert proof");
    };
    assert!(insert_proof.verify(None).is_ok());

    let account_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();

    let Proof::Insert(insert_proof) = tree.process_transaction(account_tx).unwrap() else {
        panic!("Processing transaction did not return the expected insert proof");
    };
    let service_challenge = tx_builder.get_account("service_1").unwrap().service_challenge();
    assert!(insert_proof.verify(service_challenge).is_ok());

    let Found(account, membership_proof) = tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap()
    else {
        panic!("Expected account to be found, but was not found.")
    };

    let test_account =
        tx_builder.get_account("acc_1").expect("Getting builder account should work");

    assert_eq!(*account, *test_account);
    assert!(membership_proof.verify_existence(&account).is_ok());
}

fn test_insert_for_nonexistent_service_fails(algorithm: CryptoAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_signing_key =
        SigningKey::new_with_algorithm(algorithm).expect("Failed to create service signing key");

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

fn test_insert_with_invalid_service_challenge_fails(algorithm: CryptoAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();

    // The correct way was to use the key from service registration,
    // but here we want things to break
    let incorrect_service_signing_key =
        SigningKey::new_with_algorithm(algorithm).expect("Failed to create service signing key");

    let initial_acc_signing_key =
        SigningKey::new_with_algorithm(algorithm).expect("Failed to create account signing key");

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
    assert!(insert_proof.verify(None).is_ok());

    let create_account_result = tree.process_transaction(acc_with_invalid_challenge_tx);
    assert!(create_account_result.is_err());
}

fn test_insert_duplicate_key(algorithm: CryptoAlgorithm) {
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
    assert!(insert_proof.verify(None).is_ok());

    let Proof::Insert(insert_proof) = tree.process_transaction(account_tx).unwrap() else {
        panic!("Processing Account creation failed")
    };
    let service_challenge = tx_builder.get_account("service_1").unwrap().service_challenge();
    assert!(insert_proof.verify(service_challenge).is_ok());

    let create_acc_with_same_id_result = tree.process_transaction(account_with_same_id_tx);
    assert!(create_acc_with_same_id_result.is_err());
}

fn test_update_existing_key(algorithm: CryptoAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let acc_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();

    tree.process_transaction(service_tx).unwrap();
    tree.process_transaction(acc_tx).unwrap();

    let key_tx = tx_builder.add_random_key_verified_with_root(algorithm, "acc_1").commit();

    let Proof::Update(update_proof) = tree.process_transaction(key_tx).unwrap() else {
        panic!("Processing key update failed")
    };
    assert!(update_proof.verify().is_ok());

    let get_result = tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap();
    let test_account = tx_builder.get_account("acc_1").unwrap();

    assert!(matches!(get_result, Found(acc, _) if *acc == *test_account));
}

fn test_update_non_existing_key(algorithm: CryptoAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();

    tree.process_transaction(service_tx).unwrap();

    // This is a signing key not known to the storage yet
    let random_signing_key =
        SigningKey::new_with_algorithm(algorithm).expect("Failed to create random signing key");
    // This transaction shall be invalid, because it is signed with an unknown key
    let invalid_key_tx = tx_builder.add_random_key(algorithm, "acc_1", &random_signing_key).build();

    let result = tree.process_transaction(invalid_key_tx);
    assert!(result.is_err());
}

fn test_data_ops(algorithm: CryptoAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    tree.process_transaction(service_tx).unwrap();

    let acc1_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();
    tree.process_transaction(acc1_tx).unwrap();

    let add_data_1_tx = tx_builder
        .add_internally_signed_data_verified_with_root("acc_1", b"test data 1".to_vec())
        .commit();
    let Proof::Update(update_proof) = tree.process_transaction(add_data_1_tx).unwrap() else {
        panic!("Processing data update failed");
    };
    assert!(update_proof.verify().is_ok());

    let add_data_2_tx = tx_builder
        .add_randomly_signed_data_verified_with_root(algorithm, "acc_1", b"test data 2".to_vec())
        .commit();
    let Proof::Update(update_proof) = tree.process_transaction(add_data_2_tx).unwrap() else {
        panic!("Processing signed data update failed");
    };
    assert!(update_proof.verify().is_ok());

    // Verify account data after updates
    let Found(account, membership_proof) = tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap()
    else {
        panic!("Expected account to be found after data updates");
    };

    let test_account = tx_builder.get_account("acc_1").unwrap();

    // Verify account matches expected state
    assert_eq!(*account, *test_account);
    assert!(membership_proof.verify_existence(&account).is_ok());

    // Verify data contents
    assert_eq!(account.signed_data()[0].1, b"test data 1".to_vec());
    assert_eq!(account.signed_data()[1].1, b"test data 2".to_vec());
    assert_eq!(account.signed_data().len(), 2);

    // Ensure that setData replaces, not appends
    let set_data_1_tx = tx_builder
        .set_randomly_signed_data_verified_with_root(
            algorithm,
            "acc_1",
            b"replacement data".to_vec(),
        )
        .commit();
    let Proof::Update(update_proof) = tree.process_transaction(set_data_1_tx).unwrap() else {
        panic!("Processing signed data update failed");
    };
    assert!(update_proof.verify().is_ok());

    let Found(account, _) = tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap() else {
        panic!("Expected account to be found after data updates");
    };

    // Verify data contents - should only have latest value
    assert_eq!(account.signed_data()[0].1, b"replacement data".to_vec());
    assert_eq!(account.signed_data().len(), 1);

    // Ensure incorrectly signed data leads to error

    let random_signing_key = SigningKey::new_with_algorithm(algorithm).unwrap();
    // invalid, because it does not sign the exact data we will add below
    let invalid_signature = random_signing_key.sign(b"abc");
    let invalid_signature_bundle = SignatureBundle {
        verifying_key: random_signing_key.verifying_key(),
        signature: invalid_signature,
    };

    let invalid_data_tx = tx_builder
        .add_pre_signed_data_verified_with_root(
            "acc_1",
            b"some other data".to_vec(),
            invalid_signature_bundle,
        )
        .build();
    assert!(tree.process_transaction(invalid_data_tx).is_err());
}

fn test_multiple_inserts_and_updates(algorithm: CryptoAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let acc1_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();
    let acc2_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_2", "service_1").commit();

    tree.process_transaction(service_tx).unwrap();

    tree.process_transaction(acc1_tx).unwrap();
    tree.process_transaction(acc2_tx).unwrap();

    // Do insert and update accounts using the correct key indices
    let key_1_tx = tx_builder.add_random_key_verified_with_root(algorithm, "acc_1").commit();
    tree.process_transaction(key_1_tx).unwrap();

    let data_1_tx = tx_builder
        .add_internally_signed_data_verified_with_root("acc_2", b"unsigned".to_vec())
        .commit();
    tree.process_transaction(data_1_tx).unwrap();

    let data_2_tx = tx_builder
        .add_randomly_signed_data_verified_with_root(algorithm, "acc_2", b"signed".to_vec())
        .commit();
    tree.process_transaction(data_2_tx).unwrap();

    let get_result1 = tree.get(KeyHash::with::<TreeHasher>("acc_1")).unwrap();
    let get_result2 = tree.get(KeyHash::with::<TreeHasher>("acc_2")).unwrap();

    let test_acc1 = tx_builder.get_account("acc_1").unwrap();
    let test_acc2 = tx_builder.get_account("acc_2").unwrap();

    assert!(matches!(get_result1, Found(acc, _) if *acc == *test_acc1));
    assert!(matches!(get_result2, Found(acc, _) if *acc == *test_acc2));
}

fn test_interleaved_inserts_and_updates(algorithm: CryptoAlgorithm) {
    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
    let mut tx_builder = TransactionBuilder::new();

    let service_tx = tx_builder.register_service_with_random_keys(algorithm, "service_1").commit();
    let acc1_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_1", "service_1").commit();
    let acc2_tx =
        tx_builder.create_account_with_random_key_signed(algorithm, "acc_2", "service_1").commit();

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

    let test_acc1 = tx_builder.get_account("acc_1").unwrap();
    let test_acc2 = tx_builder.get_account("acc_2").unwrap();

    assert!(matches!(get_result1, Found(acc, _) if *acc == *test_acc1));
    assert!(matches!(get_result2, Found(acc, _) if *acc == *test_acc2));
    assert_eq!(update_proof.new_root, tree.get_commitment().unwrap());
}

fn test_root_hash_changes(algorithm: CryptoAlgorithm) {
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

fn test_batch_writing(algorithm: CryptoAlgorithm) {
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

    let test_acc1 = tx_builder.get_account("acc_1").unwrap();
    let test_acc2 = tx_builder.get_account("acc_2").unwrap();

    assert!(matches!(get_result1, Found(acc, _) if *acc == *test_acc1));
    assert!(matches!(get_result2, Found(acc, _) if *acc == *test_acc2));
}

macro_rules! generate_algorithm_tests {
    ($test_fn:ident) => {
        paste::paste! {
            #[test]
            fn [<$test_fn _ed25519>]() {
                $test_fn(CryptoAlgorithm::Ed25519);
            }

            #[test]
            fn [<$test_fn _secp256k1>]() {
                $test_fn(CryptoAlgorithm::Secp256k1);
            }

            #[test]
            fn [<$test_fn _secp256r1>]() {
                $test_fn(CryptoAlgorithm::Secp256r1);
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
generate_algorithm_tests!(test_data_ops);
generate_algorithm_tests!(test_multiple_inserts_and_updates);
generate_algorithm_tests!(test_interleaved_inserts_and_updates);
generate_algorithm_tests!(test_root_hash_changes);
generate_algorithm_tests!(test_batch_writing);

#[test]
fn test_get_non_existing_key() {
    let tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));

    let result = tree.get(KeyHash::with::<TreeHasher>("non_existing_id")).unwrap();

    let NotFound(non_membership_proof) = result else {
        panic!("Account found for key while it was expected to be missing");
    };

    assert!(non_membership_proof.verify_nonexistence().is_ok());
}
