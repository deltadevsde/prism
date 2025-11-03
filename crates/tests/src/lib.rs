#![cfg(test)]

#[macro_use]
extern crate log;

use celestia_rpc::{Client, P2PClient};
use prism_common::test_transaction_builder::TestTransactionBuilder;
use prism_da::{
    DataAvailabilityLayer, FullNodeDAConfig, LightClientDAConfig, LightDataAvailabilityLayer,
    celestia::{
        CelestiaFullNodeDAConfig, CelestiaLightClientDAConfig, CelestiaLightClientDAStoreConfig,
        CelestiaNetwork, DEFAULT_PRUNING_WINDOW_IN_MEMORY,
    },
    create_full_node_da_layer, create_light_client_da_layer,
};
use prism_keys::{CryptoAlgorithm, SigningKey};
use prism_lightclient::LightClient;
use prism_prover::{
    Prover, ProverEngineOptions, ProverOptions, SequencerOptions, SyncerOptions, WebServerConfig,
};
use prism_storage::{
    Database,
    rocksdb::{RocksDBConfig, RocksDBConnection},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::sync::Arc;
use tokio::{
    spawn,
    time::{Duration, sleep},
};
use tokio_util::sync::CancellationToken;

use tempfile::TempDir;

const BRIDGE_0_ADDR: &str = "ws://localhost:26658";

fn setup_db() -> Arc<Box<dyn Database>> {
    let temp_dir = TempDir::new().unwrap();
    let cfg = RocksDBConfig::new(temp_dir.path().to_str().unwrap());
    let db = RocksDBConnection::new(&cfg).unwrap();
    Arc::new(Box::new(db) as Box<dyn Database>)
}

async fn get_bootnode(addr: &str) -> String {
    let client = Client::new(addr, None).await.unwrap();
    let peer_info = client.p2p_info().await.unwrap();
    info!("peer_info: {:?}", peer_info);
    peer_info
        .addrs
        .into_iter()
        .find(|p| {
            let p = p.to_string();
            !(p.contains("127.0.0.1") | p.contains("::1"))
        })
        .unwrap()
        .with_p2p(peer_info.id.into())
        .unwrap()
        .to_string()
}

async fn setup_da() -> (
    Arc<dyn LightDataAvailabilityLayer + std::marker::Send + std::marker::Sync + 'static>,
    Arc<dyn DataAvailabilityLayer>,
) {
    let bridge_cfg = FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig {
        url: "ws://localhost:26658".to_string(),
        ..CelestiaFullNodeDAConfig::default()
    });

    let bootnode = get_bootnode(BRIDGE_0_ADDR).await;

    let lc_cfg = LightClientDAConfig::Celestia(CelestiaLightClientDAConfig {
        celestia_network: CelestiaNetwork::Custom("private".parse().unwrap()),
        bootnodes: vec![bootnode],
        pruning_window: DEFAULT_PRUNING_WINDOW_IN_MEMORY,
        store: CelestiaLightClientDAStoreConfig::InMemory,
        ..CelestiaLightClientDAConfig::default()
    });

    let bridge_da_layer = create_full_node_da_layer(&bridge_cfg).await.unwrap();
    let lc_da_layer = create_light_client_da_layer(&lc_cfg).await.unwrap();

    (lc_da_layer, bridge_da_layer)
}

async fn setup_nodes() -> (Arc<Prover>, Arc<LightClient>, CancellationToken) {
    let db = setup_db();
    let (lc_da, fn_da) = setup_da().await;

    let prover_algorithm = CryptoAlgorithm::Ed25519;

    let signing_key = SigningKey::new_with_algorithm(prover_algorithm).unwrap();
    let pubkey = signing_key.verifying_key();

    let prover_cfg = ProverOptions {
        syncer: SyncerOptions {
            verifying_key: pubkey.clone(),
            start_height: 1,
            max_epochless_gap: 300,
            prover_enabled: true,
        },
        sequencer: SequencerOptions {
            signing_key: Some(signing_key),
            batcher_enabled: true,
        },
        prover_engine: ProverEngineOptions {
            recursive_proofs: false,
        },
        webserver: WebServerConfig::default(),
    };

    let node_shutdown_token = CancellationToken::new();

    let prover = Arc::new(
        Prover::new(
            db.clone(),
            fn_da.clone(),
            &prover_cfg,
            node_shutdown_token.clone(),
        )
        .unwrap(),
    );

    let mut lightclient = LightClient::new(lc_da.clone(), pubkey, node_shutdown_token.clone());
    lightclient.enable_mock_proof_verification();

    (prover, Arc::new(lightclient), node_shutdown_token)
}

#[tokio::test]
async fn test_light_client_prover_talking() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Debug)
        .filter_module("tracing", log::LevelFilter::Off)
        .filter_module("libp2p_gossipsub", log::LevelFilter::Off)
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
    let (prover, lightclient, node_shutdown) = setup_nodes().await;

    // Start prover node
    let prover_clone = prover.clone();
    let prover_handle = spawn(async move {
        debug!("starting prover");
        if let Err(e) = prover_clone.run().await {
            error!("Prover failed: {:?}", e);
            panic!("Prover failed: {:?}", e);
        }
    });

    // Start light client
    let lc_clone = lightclient.clone();
    let lc_handle = spawn(async move {
        debug!("starting light client");
        if let Err(e) = lc_clone.run().await {
            error!("Light client failed: {:?}", e);
            panic!("Light client failed: {:?}", e);
        }
    });

    // Start Transaction generation
    let tx_shutdown = CancellationToken::new();
    let prover_clone = Arc::clone(&prover);
    let ct = tx_shutdown.clone();
    let tx_generator = spawn(async move { generate_transactions(prover_clone, ct).await });

    // Coverage Short-Circuit
    if std::env::var("COVERAGE_TEST").is_ok() {
        sleep(Duration::from_secs(3 * 60)).await;
        return;
    }

    // Grab the latest DA height after subscribing
    let prover_clone = Arc::clone(&prover);
    let mut rx = prover_clone.get_da().subscribe_to_heights();
    let initial_height = rx.recv().await.unwrap();
    debug!("Initial height: {}", initial_height);

    // Listen for 50 heights
    let target_height = initial_height + 50;
    while let Ok(height) = rx.recv().await {
        debug!("Received height {}", height);

        if height >= target_height {
            info!("Reached target height {}.", target_height);
            // Shutdown transaction generator
            tx_shutdown.cancel();
            let res = tx_generator.await;
            assert!(
                res.is_ok(),
                "Transaction generator exited with error {:?}",
                res
            );
            break;
        }
    }

    // Ensure the light client has synced and set at least one FinalizedEpoch
    let lc_clone = Arc::clone(&lightclient);
    assert!(
        lc_clone.get_sync_state().await.latest_finalized_epoch.is_some(),
        "Light client did not sync any epochs."
    );

    // Ensure light client and prover end up with the same digest
    let lc_clone = Arc::clone(&lightclient);
    let prover_clone = Arc::clone(&prover);
    let timeout = tokio::time::timeout(Duration::from_secs(5), async move {
        loop {
            let lc_digest = lc_clone.get_latest_commitment().await.unwrap();
            let bridge_digest =
                prover_clone.get_db().get_latest_epoch().unwrap().current_commitment;
            if lc_digest == bridge_digest {
                break;
            }
            sleep(Duration::from_millis(100)).await
        }
    })
    .await;

    // Ensure the light client has synced and set at least one FinalizedEpoch
    let lc_clone = Arc::clone(&lightclient);
    assert!(
        lc_clone.get_sync_state().await.latest_finalized_epoch.is_some(),
        "Light client did not sync any epochs."
    );

    assert!(
        timeout.is_ok(),
        "Commitments did not match after timeout: {:?}",
        timeout
    );

    // Gracefully shut down nodes
    node_shutdown.cancel();
    let graceful_shutdown = tokio::try_join!(prover_handle, lc_handle);
    assert!(
        graceful_shutdown.is_ok(),
        "Nodes were not gracefully shut down: {:?}",
        graceful_shutdown
    );
}

async fn generate_transactions(prover: Arc<Prover>, ct: CancellationToken) {
    let mut rng = StdRng::from_entropy();
    let service_algorithm = random_algorithm(&mut rng);
    let mut transaction_builder = TestTransactionBuilder::new();
    let register_service_req = transaction_builder
        .register_service_with_random_keys(service_algorithm, "test_service")
        .commit();

    let mut i = 0;

    prover.clone().validate_and_queue_update(register_service_req).await.unwrap();
    let mut added_account_ids: Vec<String> = Vec::new();

    loop {
        // Check if we should shut down
        if ct.is_cancelled() {
            debug!("Transaction generator received shutdown signal");
            break;
        }

        // Create 1 to 3 new accounts
        let num_new_accounts = rng.gen_range(1..=3);
        for _ in 0..num_new_accounts {
            let random_user_id = format!("{}@gmail.com", i);
            let new_acc = transaction_builder
                .create_account_with_random_key_signed(
                    random_algorithm(&mut rng),
                    random_user_id.as_str(),
                    "test_service",
                )
                .commit();

            log::info!(
                "builder accounts: {:?}",
                transaction_builder.get_account(&random_user_id)
            );
            match prover.clone().validate_and_queue_update(new_acc).await {
                Ok(_) => {
                    i += 1;
                    added_account_ids.push(random_user_id);
                }
                Err(e) => eprintln!("Failed to create account: {}", e),
            }
        }

        // Update 5 random existing accounts (if we have at least 5)
        if added_account_ids.len() >= 5 {
            for _ in 0..5 {
                let acc_id = added_account_ids
                    .get(rng.gen_range(0..added_account_ids.len()))
                    .map_or("Could not find random account id", |id| id.as_str());

                let algorithm = random_algorithm(&mut rng);
                let update_acc = match rng.gen_range(0..3) {
                    0 => transaction_builder
                        .add_random_key_verified_with_root(algorithm, acc_id)
                        .commit(),
                    1 => transaction_builder
                        .add_randomly_signed_data_verified_with_root(
                            algorithm,
                            acc_id,
                            b"test data".to_vec(),
                        )
                        .commit(),
                    _ => transaction_builder
                        .set_randomly_signed_data_verified_with_root(
                            algorithm,
                            acc_id,
                            b"test data".to_vec(),
                        )
                        .commit(),
                };

                match prover.clone().validate_and_queue_update(update_acc).await {
                    Ok(_) => (),
                    Err(e) => eprintln!("Failed to validate and queue update: {}", e),
                };
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}

fn random_algorithm(rng: &mut StdRng) -> CryptoAlgorithm {
    [
        CryptoAlgorithm::Ed25519,
        CryptoAlgorithm::Secp256k1,
        CryptoAlgorithm::Secp256r1,
    ][rng.gen_range(0..3)]
}
