use super::*;
use prism_common::test_transaction_builder::TestTransactionBuilder;
use prism_keys::{CryptoAlgorithm, SigningKey, VerifyingKey};
use prism_tree::proofs::Proof;
use std::{self, sync::Arc, time::Duration};
use tokio::spawn;

use prism_da::memory::InMemoryDataAvailabilityLayer;
use prism_storage::inmemory::InMemoryDatabase;

// Helper function to create a test prover instance
async fn create_test_prover(algorithm: CryptoAlgorithm) -> Arc<Prover> {
    let (da_layer, _rx, _brx) = InMemoryDataAvailabilityLayer::new(1);
    let da_layer = Arc::new(da_layer);
    let db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let cfg = Config {
        max_epochless_gap: 5,
        ..Config::default_with_key_algorithm(algorithm).unwrap()
    };
    Arc::new(Prover::new(db.clone(), da_layer, &cfg).unwrap())
}

fn create_mock_transactions(algorithm: CryptoAlgorithm, service_id: String) -> Vec<Transaction> {
    let mut transaction_builder = TestTransactionBuilder::new();

    vec![
        transaction_builder.register_service_with_random_keys(algorithm, &service_id).commit(),
        transaction_builder
            .create_account_with_random_key_signed(algorithm, "user1@example.com", &service_id)
            .commit(),
        transaction_builder
            .create_account_with_random_key_signed(algorithm, "user2@example.com", &service_id)
            .commit(),
        transaction_builder
            .add_random_key_verified_with_root(algorithm, "user1@example.com")
            .commit(),
    ]
}

async fn test_posts_epoch_after_max_gap(algorithm: CryptoAlgorithm) {
    let prover = create_test_prover(algorithm).await;

    let prover_handle = prover.clone();
    spawn(async move {
        prover_handle.run().await.unwrap();
    });

    let mut rx = prover.get_da().subscribe_to_heights();

    // Wait for initial blocks to be produced
    loop {
        let height = rx.recv().await.unwrap();
        if height >= 10 {
            break;
        }
    }

    // Ensure no gap proof has been created
    assert!(prover.get_da().get_finalized_epoch(0).await.unwrap().is_none());

    // Create and submit transactions
    let test_transactions = create_mock_transactions(algorithm, "test_service".to_string());

    // Verify commitment changes after epoch finalization
    let commitment_before_epoch = prover.get_commitment().await.unwrap();
    let initial_epoch_height = prover.finalize_new_epoch(0, test_transactions).await.unwrap();
    let commitment_after_epoch = prover.get_commitment().await.unwrap();
    assert_ne!(
        commitment_before_epoch, commitment_after_epoch,
        "Commitment should change after epoch finalization"
    );

    // Give some time for the initial epoch proof to be posted
    loop {
        let height = rx.recv().await.unwrap();
        if height >= initial_epoch_height {
            break;
        }
    }
    let initial_epoch = prover.get_da().get_finalized_epoch(initial_epoch_height).await.unwrap().unwrap();

    // Wait for gap length
    loop {
        let height = rx.recv().await.unwrap();
        if height >= initial_epoch_height + 6 {
            break;
        }
    }

    let current_epoch_height = *prover.latest_epoch_da_height.read().await;

    // Give some time for the gap proof to be posted
    loop {
        let height = rx.recv().await.unwrap();
        if height >= current_epoch_height {
            break;
        }
    }
    // Verify gap proof contents
    let gap_proof = prover.get_da().get_finalized_epoch(current_epoch_height).await.unwrap().unwrap();
    assert_eq!(
        gap_proof.height,
        initial_epoch.height + 1,
        "Gap proof should be at expected height"
    );
    assert_eq!(
        gap_proof.current_commitment, commitment_after_epoch.commitment,
        "Gap proof should contain the correct commitment"
    );
}

async fn test_validate_and_queue_update(algorithm: CryptoAlgorithm) {
    let prover = create_test_prover(algorithm).await;

    let mut transaction_builder = TestTransactionBuilder::new();
    let transaction =
        transaction_builder.register_service_with_random_keys(algorithm, "test_service").commit();

    prover.clone().validate_and_queue_update(transaction.clone()).await.unwrap();

    prover.clone().validate_and_queue_update(transaction.clone()).await.unwrap();

    let pending_tx_arc = prover.get_pending_transactions();
    let pending_transactions = pending_tx_arc.read().await;
    assert_eq!(pending_transactions.len(), 2);
}

async fn test_process_transactions(algorithm: CryptoAlgorithm) {
    let prover = create_test_prover(algorithm).await;

    let mut transaction_builder = TestTransactionBuilder::new();
    let register_service_transaction =
        transaction_builder.register_service_with_random_keys(algorithm, "test_service").commit();
    let create_account_transaction = transaction_builder
        .create_account_with_random_key_signed(algorithm, "test_account", "test_service")
        .commit();

    let proof = prover.process_transaction(register_service_transaction).await.unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let proof = prover.process_transaction(create_account_transaction.clone()).await.unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let new_key = SigningKey::new_with_algorithm(algorithm).expect("Failed to create new key");
    let add_key_transaction = transaction_builder
        .add_key_verified_with_root("test_account", new_key.clone().into())
        .commit();

    let proof = prover.process_transaction(add_key_transaction).await.unwrap();

    assert!(matches!(proof, Proof::Update(_)));

    // Revoke original key
    let revoke_transaction = transaction_builder
        .revoke_key(
            "test_account",
            create_account_transaction.operation.get_public_key().cloned().unwrap(),
            &new_key,
        )
        .commit();
    let proof = prover.process_transaction(revoke_transaction).await.unwrap();
    assert!(matches!(proof, Proof::Update(_)));
}

async fn test_execute_block_with_invalid_tx(algorithm: CryptoAlgorithm) {
    let prover = create_test_prover(algorithm).await;

    let mut tx_builder = TestTransactionBuilder::new();

    let new_key_1 = SigningKey::new_with_algorithm(algorithm).expect("Failed to create new key");
    let new_key_vk: VerifyingKey = new_key_1.clone().into();

    let transactions = vec![
        tx_builder.register_service_with_random_keys(algorithm, "service_id").commit(),
        tx_builder
            .create_account_with_random_key_signed(algorithm, "account_id", "service_id")
            .commit(),
        // add new key, so it will be index = 1
        tx_builder.add_key_verified_with_root("account_id", new_key_vk.clone()).commit(),
        // revoke new key again
        tx_builder.revoke_key_verified_with_root("account_id", new_key_vk).commit(),
        // and adding in same block.
        // both of these transactions are valid individually, but when processed together it will fail.
        tx_builder.add_random_key(algorithm, "account_id", &new_key_1).build(),
    ];

    let proofs = prover.execute_block(transactions).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

async fn test_execute_block(algorithm: CryptoAlgorithm) {
    let prover = create_test_prover(algorithm).await;

    let transactions = create_mock_transactions(algorithm, "test_service".to_string());

    let proofs = prover.execute_block(transactions).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

async fn test_finalize_new_epoch(algorithm: CryptoAlgorithm) {
    let prover = create_test_prover(algorithm).await;
    let transactions = create_mock_transactions(algorithm, "test_service".to_string());

    let prev_commitment = prover.get_commitment().await.unwrap();
    prover.finalize_new_epoch(0, transactions).await.unwrap();

    let new_commitment = prover.get_commitment().await.unwrap();
    assert_ne!(prev_commitment, new_commitment);
}

async fn test_restart_sync_from_scratch(algorithm: CryptoAlgorithm) {
    let (da_layer, _rx, mut brx) = InMemoryDataAvailabilityLayer::new(1);
    let da_layer = Arc::new(da_layer);
    let db1: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let db2: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let cfg = Config::default_with_key_algorithm(algorithm).unwrap();
    let prover = Arc::new(Prover::new(db1.clone(), da_layer.clone(), &cfg).unwrap());

    let runner = prover.clone();
    spawn(async move {
        runner.run().await.unwrap();
    });

    let transactions = create_mock_transactions(algorithm, "test_service".to_string());

    for transaction in transactions {
        prover.validate_and_queue_update(transaction).await.unwrap();
        while let Ok(new_block) = brx.recv().await {
            if new_block.epoch.is_some() {
                break;
            }
        }
    }

    assert_eq!(prover.get_db().get_latest_epoch_height().unwrap(), 3);

    let prover2 = Arc::new(Prover::new(db2.clone(), da_layer.clone(), &cfg).unwrap());
    let runner = prover2.clone();
    spawn(async move { runner.run().await.unwrap() });

    loop {
        let epoch = prover2.get_db().get_latest_epoch_height();
        if epoch.is_ok() && epoch.unwrap() == 3 {
            assert_eq!(
                prover.get_commitment().await.unwrap(),
                prover2.get_commitment().await.unwrap()
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn test_load_persisted_state(algorithm: CryptoAlgorithm) {
    let (da_layer, _rx, mut brx) = InMemoryDataAvailabilityLayer::new(1);
    let da_layer = Arc::new(da_layer);
    let db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let cfg = Config::default_with_key_algorithm(algorithm).unwrap();
    let prover = Arc::new(Prover::new(db.clone(), da_layer.clone(), &cfg).unwrap());

    let runner = prover.clone();
    spawn(async move {
        runner.run().await.unwrap();
    });

    let transactions = create_mock_transactions(algorithm, "test_service".to_string());

    for transaction in transactions {
        prover.validate_and_queue_update(transaction).await.unwrap();
        while let Ok(new_block) = brx.recv().await {
            if new_block.epoch.is_some() {
                break;
            }
        }
    }

    assert_eq!(prover.get_db().get_latest_epoch_height().unwrap(), 3);

    let prover2 = Arc::new(Prover::new(db.clone(), da_layer.clone(), &cfg).unwrap());
    let runner = prover2.clone();
    spawn(async move { runner.run().await.unwrap() });
    let epoch = prover2.get_db().get_latest_epoch_height().unwrap();
    assert_eq!(epoch, 3);
    assert_eq!(
        prover.get_commitment().await.unwrap(),
        prover2.get_commitment().await.unwrap()
    );
}

macro_rules! generate_algorithm_tests {
    ($test_fn:ident) => {
        paste::paste! {
            #[tokio::test]
            async fn [<$test_fn _ed25519>]() {
                $test_fn(CryptoAlgorithm::Ed25519).await;
            }

            #[tokio::test]
            async fn [<$test_fn _secp256k1>]() {
                $test_fn(CryptoAlgorithm::Secp256k1).await;
            }

            #[tokio::test]
            async fn [<$test_fn _secp256r1>]() {
                $test_fn(CryptoAlgorithm::Secp256r1).await;
            }
        }
    };
}

generate_algorithm_tests!(test_validate_and_queue_update);
generate_algorithm_tests!(test_process_transactions);
generate_algorithm_tests!(test_execute_block_with_invalid_tx);
generate_algorithm_tests!(test_execute_block);
generate_algorithm_tests!(test_finalize_new_epoch);
generate_algorithm_tests!(test_restart_sync_from_scratch);
generate_algorithm_tests!(test_load_persisted_state);
generate_algorithm_tests!(test_posts_epoch_after_max_gap);
