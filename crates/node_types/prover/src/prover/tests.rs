use super::*;
use prism_common::{transaction_builder::TransactionBuilder, tree::Proof};
use prism_keys::{SigningKey, VerifyingKey};
use std::{self, sync::Arc, time::Duration};
use tokio::spawn;

use prism_da::memory::InMemoryDataAvailabilityLayer;
use prism_storage::{inmemory::InMemoryDatabase, Database};

// Helper function to create a test prover instance
async fn create_test_prover() -> Arc<Prover> {
    let (da_layer, _rx, _brx) = InMemoryDataAvailabilityLayer::new(1);
    let da_layer = Arc::new(da_layer);
    let db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let cfg = Config::default();
    Arc::new(Prover::new(db.clone(), da_layer, &cfg).unwrap())
}

fn create_mock_transactions(service_id: String) -> Vec<Transaction> {
    let mut transaction_builder = TransactionBuilder::new();

    vec![
        transaction_builder.register_service_with_random_keys(&service_id).commit(),
        transaction_builder
            .create_account_with_random_key("user1@example.com", &service_id)
            .commit(),
        transaction_builder
            .create_account_with_random_key("user2@example.com", &service_id)
            .commit(),
        transaction_builder.add_random_key_verified_with_root("user1@example.com").commit(),
    ]
}

#[tokio::test]
async fn test_validate_and_queue_update() {
    let prover = create_test_prover().await;

    let mut transaction_builder = TransactionBuilder::new();
    let transaction =
        transaction_builder.register_service_with_random_keys("test_service").commit();

    prover.clone().validate_and_queue_update(transaction.clone()).await.unwrap();

    prover.clone().validate_and_queue_update(transaction.clone()).await.unwrap();

    let pending_transactions = prover.pending_transactions.read().await;
    assert_eq!(pending_transactions.len(), 2);
}

#[tokio::test]
async fn test_process_transactions() {
    let prover = create_test_prover().await;

    let mut transaction_builder = TransactionBuilder::new();
    let register_service_transaction =
        transaction_builder.register_service_with_random_keys("test_service").commit();
    let create_account_transaction =
        transaction_builder.create_account_with_random_key("test_account", "test_service").commit();

    let proof = prover.process_transaction(register_service_transaction).await.unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let proof = prover.process_transaction(create_account_transaction.clone()).await.unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let new_key = SigningKey::new_ed25519();
    let add_key_transaction = transaction_builder
        .add_key_verified_with_root("test_account", new_key.clone().into())
        .commit();

    let proof = prover.process_transaction(add_key_transaction).await.unwrap();

    assert!(matches!(proof, Proof::Update(_)));

    // Revoke original key
    let revoke_transaction = transaction_builder
        .revoke_key(
            "test_account",
            create_account_transaction.entry.operation.get_public_key().cloned().unwrap(),
            &new_key,
            1,
        )
        .commit();
    let proof = prover.process_transaction(revoke_transaction).await.unwrap();
    assert!(matches!(proof, Proof::Update(_)));
}

#[tokio::test]
async fn test_execute_block_with_invalid_tx() {
    let prover = create_test_prover().await;

    let mut tx_builder = TransactionBuilder::new();

    let new_key_1 = SigningKey::new_ed25519();
    let new_key_vk: VerifyingKey = new_key_1.clone().into();

    let transactions = vec![
        tx_builder.register_service_with_random_keys("service_id").commit(),
        tx_builder.create_account_with_random_key("account_id", "service_id").commit(),
        // add new key, so it will be index = 1
        tx_builder.add_key_verified_with_root("account_id", new_key_vk.clone()).commit(),
        // revoke new key again
        tx_builder.revoke_key_verified_with_root("account_id", new_key_vk).commit(),
        // and adding in same block.
        // both of these transactions are valid individually, but when processed together it will fail.
        tx_builder.add_random_key("account_id", &new_key_1, 1).build(),
    ];

    let proofs = prover.execute_block(transactions).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

#[tokio::test]
async fn test_execute_block() {
    let prover = create_test_prover().await;

    let transactions = create_mock_transactions("test_service".to_string());

    let proofs = prover.execute_block(transactions).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

#[tokio::test]
async fn test_finalize_new_epoch() {
    let prover = create_test_prover().await;
    let transactions = create_mock_transactions("test_service".to_string());

    let prev_commitment = prover.get_commitment().await.unwrap();
    prover.finalize_new_epoch(0, transactions).await.unwrap();

    let new_commitment = prover.get_commitment().await.unwrap();
    assert_ne!(prev_commitment, new_commitment);
}

#[tokio::test]
async fn test_restart_sync_from_scratch() {
    let (da_layer, _rx, mut brx) = InMemoryDataAvailabilityLayer::new(1);
    let da_layer = Arc::new(da_layer);
    let db1: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let db2: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let cfg = Config::default();
    let prover = Arc::new(Prover::new(db1.clone(), da_layer.clone(), &cfg).unwrap());

    let runner = prover.clone();
    spawn(async move {
        runner.run().await.unwrap();
    });

    let transactions = create_mock_transactions("test_service".to_string());

    for transaction in transactions {
        prover.clone().validate_and_queue_update(transaction).await.unwrap();
        while let Ok(new_block) = brx.recv().await {
            if new_block.epoch.is_some() {
                break;
            }
        }
    }

    assert_eq!(prover.clone().db.get_epoch().unwrap(), 4);

    let prover2 = Arc::new(Prover::new(db2.clone(), da_layer.clone(), &cfg).unwrap());
    let runner = prover2.clone();
    spawn(async move { runner.run().await.unwrap() });

    loop {
        let epoch = prover2.clone().db.get_epoch().unwrap();
        if epoch == 4 {
            assert_eq!(
                prover.get_commitment().await.unwrap(),
                prover2.get_commitment().await.unwrap()
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn test_load_persisted_state() {
    let (da_layer, _rx, mut brx) = InMemoryDataAvailabilityLayer::new(1);
    let da_layer = Arc::new(da_layer);
    let db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let cfg = Config::default();
    let prover = Arc::new(Prover::new(db.clone(), da_layer.clone(), &cfg).unwrap());

    let runner = prover.clone();
    spawn(async move {
        runner.run().await.unwrap();
    });

    let transactions = create_mock_transactions("test_service".to_string());

    for transaction in transactions {
        prover.clone().validate_and_queue_update(transaction).await.unwrap();
        while let Ok(new_block) = brx.recv().await {
            if new_block.epoch.is_some() {
                break;
            }
        }
    }

    assert_eq!(prover.clone().db.get_epoch().unwrap(), 4);

    let prover2 = Arc::new(Prover::new(db.clone(), da_layer.clone(), &cfg).unwrap());
    let runner = prover2.clone();
    spawn(async move { runner.run().await.unwrap() });
    let epoch = prover2.clone().db.get_epoch().unwrap();
    assert_eq!(epoch, 4);
    assert_eq!(
        prover.get_commitment().await.unwrap(),
        prover2.get_commitment().await.unwrap()
    );
}
