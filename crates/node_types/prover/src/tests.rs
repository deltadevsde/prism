use prism_common::tree::Proof;
use std::{self, sync::Arc};

use crate::{Config, Prover};
use prism_common::{operation::Operation, test_utils::create_mock_signing_key};
use prism_da::memory::InMemoryDataAvailabilityLayer;
use prism_storage::{inmemory::InMemoryDatabase, Database};

// Helper function to create a test prover instance
async fn create_test_prover() -> Arc<Prover> {
    let (da_layer, _rx, _brx) = InMemoryDataAvailabilityLayer::new(1);
    let da_layer = Arc::new(da_layer);
    let db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let cfg = Config::default();
    Arc::new(Prover::new(db.clone(), da_layer, cfg.clone()).unwrap())
}

#[tokio::test]
async fn test_validate_and_queue_update() {
    let prover = create_test_prover().await;

    let service_key = create_mock_signing_key();
    let op = Operation::new_register_service("service_id".to_string(), service_key.clone().into());

    prover.clone().validate_and_queue_update(&op).await.unwrap();

    prover.clone().validate_and_queue_update(&op).await.unwrap();

    let pending_ops = prover.pending_operations.read().await;
    assert_eq!(pending_ops.len(), 2);
}

#[tokio::test]
async fn test_process_operation() {
    let prover = create_test_prover().await;

    let signing_key = create_mock_signing_key();
    let original_pubkey = signing_key.verifying_key();
    let service_key = create_mock_signing_key();

    let register_service_op =
        Operation::new_register_service("service_id".to_string(), service_key.clone().into());
    let create_account_op = Operation::new_create_account(
        "test@example.com".to_string(),
        &signing_key,
        "service_id".to_string(),
        &service_key,
    )
    .unwrap();

    let proof = prover
        .process_operation(&register_service_op)
        .await
        .unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let proof = prover.process_operation(&create_account_op).await.unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let new_key = create_mock_signing_key();
    let pubkey = new_key.verifying_key();
    let add_key_op =
        Operation::new_add_key("test@example.com".to_string(), pubkey, &signing_key, 0).unwrap();

    let proof = prover.process_operation(&add_key_op).await.unwrap();

    assert!(matches!(proof, Proof::Update(_)));

    // Revoke original key
    let revoke_op =
        Operation::new_revoke_key("test@example.com".to_string(), original_pubkey, &new_key, 1)
            .unwrap();
    let proof = prover.process_operation(&revoke_op).await.unwrap();
    assert!(matches!(proof, Proof::Update(_)));
}

#[tokio::test]
async fn test_execute_block_with_invalid_tx() {
    let prover = create_test_prover().await;

    let signing_key_1 = create_mock_signing_key();
    let signing_key_2 = create_mock_signing_key();
    let signing_key_3 = create_mock_signing_key();
    let service_key = create_mock_signing_key();

    let operations = vec![
        Operation::new_register_service("service_id".to_string(), service_key.clone().into()),
        Operation::new_create_account(
            "user1@example.com".to_string(),
            &signing_key_1,
            "service_id".to_string(),
            &service_key,
        )
        .unwrap(),
        // add signing_key_2, so it will be index = 1
        Operation::new_add_key(
            "user1@example.com".to_string(),
            signing_key_2.verifying_key(),
            &signing_key_1,
            0,
        )
        .unwrap(),
        // try revoking signing_key_2
        Operation::new_revoke_key(
            "user1@example.com".to_string(),
            signing_key_2.verifying_key(),
            &signing_key_1,
            0,
        )
        .unwrap(),
        // and adding in same block.
        // both of these operations are valid individually, but when processed together it will fail.
        Operation::new_add_key(
            "user1@example.com".to_string(),
            signing_key_3.verifying_key(),
            &signing_key_2,
            1,
        )
        .unwrap(),
    ];

    let proofs = prover.execute_block(operations).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

#[tokio::test]
async fn test_execute_block() {
    let prover = create_test_prover().await;

    let signing_key_1 = create_mock_signing_key();
    let signing_key_2 = create_mock_signing_key();
    let new_key = create_mock_signing_key().verifying_key();
    let service_key = create_mock_signing_key();

    let operations = vec![
        Operation::new_register_service("service_id".to_string(), service_key.clone().into()),
        Operation::new_create_account(
            "user1@example.com".to_string(),
            &signing_key_1,
            "service_id".to_string(),
            &service_key,
        )
        .unwrap(),
        Operation::new_create_account(
            "user2@example.com".to_string(),
            &signing_key_2,
            "service_id".to_string(),
            &service_key,
        )
        .unwrap(),
        Operation::new_add_key("user1@example.com".to_string(), new_key, &signing_key_1, 0)
            .unwrap(),
    ];

    let proofs = prover.execute_block(operations).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

#[tokio::test]
async fn test_finalize_new_epoch() {
    let prover = create_test_prover().await;

    let signing_key_1 = create_mock_signing_key();
    let signing_key_2 = create_mock_signing_key();
    let new_key = create_mock_signing_key().verifying_key();
    let service_key = create_mock_signing_key();

    let operations = vec![
        Operation::new_register_service("service_id".to_string(), service_key.clone().into()),
        Operation::new_create_account(
            "user1@example.com".to_string(),
            &signing_key_1,
            "service_id".to_string(),
            &service_key,
        )
        .unwrap(),
        Operation::new_create_account(
            "user2@example.com".to_string(),
            &signing_key_2,
            "service_id".to_string(),
            &service_key,
        )
        .unwrap(),
        Operation::new_add_key("user1@example.com".to_string(), new_key, &signing_key_1, 0)
            .unwrap(),
    ];

    let prev_commitment = prover.get_commitment().await.unwrap();
    prover.finalize_new_epoch(0, operations).await.unwrap();

    let new_commitment = prover.get_commitment().await.unwrap();
    assert_ne!(prev_commitment, new_commitment);
}
