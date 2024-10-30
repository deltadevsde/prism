use super::*;
use prism_common::{test_ops::OpsBuilder, tree::Proof};
use std::{self, sync::Arc, time::Duration};
use tokio::spawn;

use prism_common::{operation::Operation, test_utils::create_mock_signing_key};
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

fn create_mock_operations(service_id: String) -> Vec<Operation> {
    let mut ops_builder = OpsBuilder::new();

    vec![
        ops_builder.register_service_with_random_key(&service_id).ex(),
        ops_builder.create_account_with_random_key("user1@example.com", &service_id).ex(),
        ops_builder.create_account_with_random_key("user2@example.com", &service_id).ex(),
        ops_builder.add_random_key_verified_with_root("user1@example.com").ex(),
    ]
}

#[tokio::test]
async fn test_validate_and_queue_update() {
    let prover = create_test_prover().await;

    let mut ops_builder = OpsBuilder::new();
    let op = ops_builder.register_service_with_random_key("test_service").ex();

    prover.clone().validate_and_queue_update(&op).await.unwrap();

    prover.clone().validate_and_queue_update(&op).await.unwrap();

    let pending_ops = prover.pending_operations.read().await;
    assert_eq!(pending_ops.len(), 2);
}

#[tokio::test]
async fn test_process_operation() {
    let prover = create_test_prover().await;

    let mut ops_builder = OpsBuilder::new();
    let register_service_op = ops_builder.register_service_with_random_key("test_service").ex();
    let create_account_op =
        ops_builder.create_account_with_random_key("test_account", "test_service").ex();

    let proof = prover.process_operation(&register_service_op).await.unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let proof = prover.process_operation(&create_account_op).await.unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let new_key = create_mock_signing_key();
    let add_key_op =
        ops_builder.add_key_verified_with_root("test_account", new_key.verifying_key()).ex();

    let proof = prover.process_operation(&add_key_op).await.unwrap();

    assert!(matches!(proof, Proof::Update(_)));

    // Revoke original key
    let revoke_op = ops_builder
        .revoke_key(
            "test_account",
            create_account_op.get_public_key().cloned().unwrap(),
            &new_key,
            1,
        )
        .ex();
    let proof = prover.process_operation(&revoke_op).await.unwrap();
    assert!(matches!(proof, Proof::Update(_)));
}

#[tokio::test]
async fn test_execute_block_with_invalid_tx() {
    let prover = create_test_prover().await;

    let mut ops_builder = OpsBuilder::new();

    let new_key_1 = create_mock_signing_key();

    let operations = vec![
        ops_builder.register_service_with_random_key("service_id").ex(),
        ops_builder.create_account_with_random_key("account_id", "service_id").ex(),
        // add new key, so it will be index = 1
        ops_builder.add_key_verified_with_root("account_id", new_key_1.verifying_key()).ex(),
        // revoke new key again
        ops_builder.revoke_key_verified_with_root("account_id", new_key_1.verifying_key()).ex(),
        // and adding in same block.
        // both of these operations are valid individually, but when processed together it will fail.
        ops_builder.add_random_key("account_id", &new_key_1, 1).op(),
    ];

    let proofs = prover.execute_block(operations).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

#[tokio::test]
async fn test_execute_block() {
    let prover = create_test_prover().await;

    let operations = create_mock_operations("test_service".to_string());

    let proofs = prover.execute_block(operations).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

#[tokio::test]
async fn test_finalize_new_epoch() {
    let prover = create_test_prover().await;
    let operations = create_mock_operations("test_service".to_string());

    let prev_commitment = prover.get_commitment().await.unwrap();
    prover.finalize_new_epoch(0, operations).await.unwrap();

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

    let operations = create_mock_operations("test_service".to_string());

    for op in operations {
        prover.clone().validate_and_queue_update(&op).await.unwrap();
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

    let operations = create_mock_operations("test_service".to_string());

    for op in operations {
        prover.clone().validate_and_queue_update(&op).await.unwrap();
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
