use crate::prover_engine::engine::MockProverEngine;

use super::*;
use prism_common::test_transaction_builder::TestTransactionBuilder;
use prism_da::{SuccinctProof, VerifiableEpoch, memory::InMemoryDataAvailabilityLayer};
use prism_keys::{CryptoAlgorithm, SigningKey, VerifyingKey};
use prism_storage::inmemory::InMemoryDatabase;
use prism_tree::proofs::{Batch, Proof};
use std::{self, sync::Arc, time::Duration};

fn init_logger() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Debug)
        .filter_module("tracing", log::LevelFilter::Off)
        .filter_module("sp1_stark", log::LevelFilter::Info)
        .filter_module("jmt", log::LevelFilter::Off)
        .filter_module("p3_dft", log::LevelFilter::Off)
        .filter_module("p3_fri", log::LevelFilter::Off)
        .filter_module("sp1_core_executor", log::LevelFilter::Info)
        .filter_module("sp1_recursion_program", log::LevelFilter::Info)
        .filter_module("sp1_prover", log::LevelFilter::Info)
        .filter_module("p3_merkle_tree", log::LevelFilter::Off)
        .filter_module("sp1_recursion_compiler", log::LevelFilter::Off)
        .filter_module("sp1_core_machine", log::LevelFilter::Off)
        .init();
}

// Helper function to create a test prover instance
async fn create_test_prover(algorithm: CryptoAlgorithm) -> Arc<Prover> {
    let (da_layer, _rx, _brx) = InMemoryDataAvailabilityLayer::new(Duration::from_millis(50));
    let da_layer = Arc::new(da_layer);
    let db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let mut opts = ProverOptions::default_with_key_algorithm(algorithm).unwrap();
    opts.syncer.max_epochless_gap = 5;
    opts.webserver.port = 0;
    let engine = create_mock_engine().await;
    Arc::new(Prover::new_with_engine(db.clone(), da_layer, engine.clone(), &opts).unwrap())
}

async fn create_mock_engine() -> Arc<dyn ProverEngine> {
    let mut engine = MockProverEngine::new();
    engine.expect_prove_epoch().returning(|_: u64, batch: &Batch, _: &Arc<Box<dyn Database>>| {
        match batch.verify() {
            Ok(_) => Ok((SuccinctProof::default(), SuccinctProof::default())),
            Err(e) => Err(anyhow!(e)),
        }
    });

    // TODO: Maybe mock the verifiable epochs somehow as well
    engine.expect_verify_proof().returning(|_: VerifiableEpoch| Ok(()));
    Arc::new(engine)
}

fn create_mock_transactions(service_id: String) -> Vec<Transaction> {
    let mut transaction_builder = TestTransactionBuilder::new();

    vec![
        transaction_builder
            .register_service_with_random_keys(CryptoAlgorithm::Ed25519, &service_id)
            .commit(),
        transaction_builder
            .create_account_with_random_key_signed(
                CryptoAlgorithm::Secp256k1,
                "user1@example.com",
                &service_id,
            )
            .commit(),
        transaction_builder
            .create_account_with_random_key_signed(
                CryptoAlgorithm::Secp256r1,
                "user2@example.com",
                &service_id,
            )
            .commit(),
        transaction_builder
            .add_random_key_verified_with_root(CryptoAlgorithm::Ed25519, "user1@example.com")
            .commit(),
    ]
}

#[tokio::test]
async fn test_posts_epoch_after_max_gap() {
    init_logger();
    let prover = create_test_prover(CryptoAlgorithm::Ed25519).await;
    prover.start().await.expect("Prover can be started");

    let mut rx = prover.get_da().subscribe_to_heights();

    // Wait for initial blocks to be produced
    loop {
        let height = rx.recv().await.unwrap();
        if height >= 10 {
            break;
        }
    }

    // Ensure no gap proof has been created
    assert!(prover.get_da().get_finalized_epochs(0).await.unwrap().is_empty());

    // Create and submit transactions
    let test_transactions = create_mock_transactions("test_service".to_string());

    // Verify commitment changes after epoch finalization
    let commitment_before_epoch = prover.get_commitment().await.unwrap();
    let initial_epoch_height = prover.finalize_new_epoch(0, test_transactions, 0).await.unwrap();
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
    let epochs = prover.get_da().get_finalized_epochs(initial_epoch_height).await.unwrap();
    let initial_epoch = epochs.first().unwrap();

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
    let epochs = prover.get_da().get_finalized_epochs(current_epoch_height).await.unwrap();
    let gap_proof = epochs.first().unwrap();
    let commitments = gap_proof.commitments();
    let current_commitment = commitments.current;
    assert_eq!(
        gap_proof.height(),
        initial_epoch.height() + 1,
        "Gap proof should be at expected height"
    );
    assert_eq!(
        current_commitment, commitment_after_epoch.commitment,
        "Gap proof should contain the correct commitment"
    );

    prover.stop().await.expect("Prover can be stopped");
}

async fn test_validate_and_queue_update(algorithm: CryptoAlgorithm) {
    init_logger();
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

#[tokio::test]
async fn test_process_transactions() {
    init_logger();
    let prover = create_test_prover(CryptoAlgorithm::Ed25519).await;

    let mut transaction_builder = TestTransactionBuilder::new();
    let register_service_transaction = transaction_builder
        .register_service_with_random_keys(CryptoAlgorithm::Ed25519, "test_service")
        .commit();
    let create_account_transaction = transaction_builder
        .create_account_with_random_key_signed(
            CryptoAlgorithm::Secp256k1,
            "test_account",
            "test_service",
        )
        .commit();

    let proof = prover.process_transaction(register_service_transaction).await.unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let proof = prover.process_transaction(create_account_transaction.clone()).await.unwrap();
    assert!(matches!(proof, Proof::Insert(_)));

    let new_key = SigningKey::new_with_algorithm(CryptoAlgorithm::Secp256r1)
        .expect("Failed to create new key");
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

#[tokio::test]
async fn test_execute_block_with_invalid_tx() {
    init_logger();
    let prover = create_test_prover(CryptoAlgorithm::Ed25519).await;

    let mut tx_builder = TestTransactionBuilder::new();

    let new_key_1 = SigningKey::new_with_algorithm(CryptoAlgorithm::Secp256r1)
        .expect("Failed to create new key");
    let new_key_vk: VerifyingKey = new_key_1.clone().into();

    let transactions = vec![
        tx_builder
            .register_service_with_random_keys(CryptoAlgorithm::Secp256r1, "service_id")
            .commit(),
        tx_builder
            .create_account_with_random_key_signed(
                CryptoAlgorithm::Secp256k1,
                "account_id",
                "service_id",
            )
            .commit(),
        // add new key, so it will be index = 1
        tx_builder.add_key_verified_with_root("account_id", new_key_vk.clone()).commit(),
        // revoke new key again
        tx_builder.revoke_key_verified_with_root("account_id", new_key_vk).commit(),
        // and adding in same block.
        // both of these transactions are valid individually, but when processed together it will
        // fail.
        tx_builder.add_random_key(CryptoAlgorithm::Secp256k1, "account_id", &new_key_1).build(),
    ];

    let proofs = prover.execute_block(transactions).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

#[tokio::test]
async fn test_execute_block() {
    init_logger();
    let prover = create_test_prover(CryptoAlgorithm::Ed25519).await;

    let transactions = create_mock_transactions("test_service".to_string());

    let proofs = prover.execute_block(transactions).await.unwrap();
    assert_eq!(proofs.len(), 4);
}

#[tokio::test]
async fn test_finalize_new_epoch() {
    init_logger();
    let prover = create_test_prover(CryptoAlgorithm::Ed25519).await;
    let transactions = create_mock_transactions("test_service".to_string());

    let prev_commitment = prover.get_commitment().await.unwrap();
    prover.finalize_new_epoch(0, transactions, 0).await.unwrap();

    let new_commitment = prover.get_commitment().await.unwrap();
    assert_ne!(prev_commitment, new_commitment);
}

#[tokio::test]
async fn test_restart_sync_from_scratch() {
    init_logger();
    let (da_layer, _rx, mut brx) = InMemoryDataAvailabilityLayer::new(Duration::from_millis(50));
    let da_layer = Arc::new(da_layer);
    let db1: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let db2: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let engine = create_mock_engine().await;
    let mut opts = ProverOptions::default_with_key_algorithm(CryptoAlgorithm::Ed25519).unwrap();
    opts.webserver.port = 0;
    let prover =
        Prover::new_with_engine(db1.clone(), da_layer.clone(), engine.clone(), &opts).unwrap();
    prover.start().await.expect("Prover can be started");

    let transactions = create_mock_transactions("test_service".to_string());

    for transaction in transactions {
        prover.validate_and_queue_update(transaction).await.unwrap();
        while let Ok(new_block) = brx.recv().await {
            if !new_block.epochs.is_empty() {
                break;
            }
        }
    }

    assert_eq!(prover.get_db().get_latest_epoch_height().unwrap(), 3);
    let latest_commitment = prover.get_commitment().await.unwrap();
    prover.stop().await.expect("Prover can be stopped");

    let prover2 = Arc::new(
        Prover::new_with_engine(db2.clone(), da_layer.clone(), engine.clone(), &opts).unwrap(),
    );
    drop(db1);
    drop(prover);
    prover2.start().await.expect("Prover2 can be started");

    let prover2_clone = prover2.clone();
    let res = tokio::time::timeout(Duration::from_secs(120), async move {
        // Poll until prover2 syncs to epoch 3, checking every 200ms
        loop {
            let epoch = prover2_clone.get_db().get_latest_epoch_height();
            if epoch.is_ok() && epoch.unwrap() == 3 {
                // Verify that commitments match after sync
                assert_eq!(
                    latest_commitment,
                    prover2_clone.get_commitment().await.unwrap()
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;

    assert!(res.is_ok());
}

#[tokio::test]
async fn test_prover_fullnode_commitment_sync_with_racing_transactions() {
    init_logger();
    // Setup shared DA layer
    let (da_layer, _rx, mut brx) = InMemoryDataAvailabilityLayer::new_with_epoch_delay(
        Duration::from_millis(50),
        Duration::from_millis(250),
    );
    let da_layer = Arc::new(da_layer);

    // Setup prover (with prover enabled)
    let prover_db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let prover_engine = create_mock_engine().await;
    let mut prover_opts =
        ProverOptions::default_with_key_algorithm(CryptoAlgorithm::Ed25519).unwrap();
    prover_opts.syncer.prover_enabled = true;
    prover_opts.webserver.port = 0;
    let prover = Prover::new_with_engine(
        prover_db.clone(),
        da_layer.clone(),
        prover_engine.clone(),
        &prover_opts,
    )
    .unwrap();

    // Setup fullnode (with prover disabled) - use same verifying key as prover
    let fullnode_db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let fullnode_engine = create_mock_engine().await;
    let mut fullnode_opts =
        ProverOptions::default_with_key_algorithm(CryptoAlgorithm::Ed25519).unwrap();
    fullnode_opts.syncer.prover_enabled = false;
    fullnode_opts.syncer.verifying_key = prover_opts.syncer.verifying_key.clone();
    fullnode_opts.webserver.port = 0;
    let fullnode = Prover::new_with_engine(
        fullnode_db.clone(),
        da_layer.clone(),
        fullnode_engine.clone(),
        &fullnode_opts,
    )
    .unwrap();

    // Start both nodes
    prover.start().await.expect("Prover can be started");
    fullnode.start().await.expect("Fullnode can be started");

    // Wait for both nodes to boot up
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Ensure both nodes are at the same height before proceeding
    let mut prover_synced = false;
    let mut fullnode_synced = false;

    for _ in 0..10 {
        // 5 second timeout
        let prover_height = prover.get_db().get_last_synced_height().unwrap_or(0);
        let fullnode_height = fullnode.get_db().get_last_synced_height().unwrap_or(0);
        let da_height = da_layer.get_latest_height().await.unwrap();

        if prover_height >= da_height && prover_height > 0 {
            prover_synced = true;
        }
        if fullnode_height >= da_height && fullnode_height > 0 {
            fullnode_synced = true;
        }

        if prover_synced && fullnode_synced {
            break;
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    assert!(
        prover_synced && fullnode_synced,
        "Nodes failed to sync before test"
    );

    // Create all transactions and split them
    let all_transactions = create_mock_transactions("test_service".to_string());
    let (initial_transactions, racing_transactions) = all_transactions.split_at(1);

    // Submit initial transaction for prover to process
    for transaction in initial_transactions {
        da_layer.submit_transactions(vec![transaction.clone()]).await.unwrap();
    }

    // Wait a bit for transactions to be processed
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Submit racing transactions that arrive while prover is creating proof
    for transaction in racing_transactions {
        da_layer.submit_transactions(vec![transaction.clone()]).await.unwrap();
    }

    // Wait for the prover to create and publish an epoch (this should happen with the racing
    // transactions buffered)
    let mut epoch_found = false;
    while let Ok(new_block) = brx.recv().await {
        if !new_block.epochs.is_empty() {
            epoch_found = true;
            break;
        }
    }
    assert!(epoch_found, "Prover should have created an epoch");

    // Wait for fullnode to sync the epoch
    while prover.get_commitment().await.unwrap() != fullnode.get_commitment().await.unwrap() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Both nodes should have the same commitment despite racing transactions
    let prover_commitment = prover.get_commitment().await.unwrap();
    let fullnode_commitment = fullnode.get_commitment().await.unwrap();

    assert_eq!(
        prover_commitment, fullnode_commitment,
        "Prover and fullnode should have matching commitments even with racing transactions"
    );

    // Verify they are at the same epoch height
    let prover_epoch = prover.get_db().get_latest_epoch_height().unwrap();
    let fullnode_epoch = fullnode.get_db().get_latest_epoch_height().unwrap();
    assert_eq!(
        prover_epoch, fullnode_epoch,
        "Both nodes should be at the same epoch height"
    );
}

#[tokio::test]
async fn test_load_persisted_state() {
    init_logger();
    let (da_layer, _rx, mut brx) = InMemoryDataAvailabilityLayer::new(Duration::from_millis(50));
    let da_layer = Arc::new(da_layer);
    let db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
    let engine = create_mock_engine().await;
    let mut opts = ProverOptions::default_with_key_algorithm(CryptoAlgorithm::Ed25519).unwrap();
    opts.webserver.port = 0;
    let prover =
        Prover::new_with_engine(db.clone(), da_layer.clone(), engine.clone(), &opts).unwrap();
    prover.start().await.expect("Prover can be started");

    let transactions = create_mock_transactions("test_service".to_string());

    for transaction in transactions {
        prover.validate_and_queue_update(transaction).await.unwrap();
        while let Ok(new_block) = brx.recv().await {
            if !new_block.epochs.is_empty() {
                break;
            }
        }
    }

    assert_eq!(prover.get_db().get_latest_epoch_height().unwrap(), 3);

    let prover2 =
        Prover::new_with_engine(db.clone(), da_layer.clone(), engine.clone(), &opts).unwrap();
    prover2.start().await.expect("Prover2 can be started");

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
