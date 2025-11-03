#![cfg(test)]

#[macro_use]
extern crate log;

use celestia_rpc::{Client, P2PClient};
use prism_common::test_transaction_builder::TestTransactionBuilder;
use prism_da::{
    FullNodeDAConfig, LightClientDAConfig,
    celestia::{
        CelestiaFullNodeDAConfig, CelestiaLightClientDAConfig, CelestiaLightClientDAStoreConfig,
        CelestiaNetwork, DEFAULT_PRUNING_WINDOW_IN_MEMORY,
    },
};
use prism_keys::{CryptoAlgorithm, SigningKey};
use prism_lightclient::{LightClient, LightClientConfig, create_light_client};
use prism_prover::{Prover, ProverConfig, WebServerConfig, create_prover_as_prover};
use prism_storage::{DatabaseConfig, rocksdb::RocksDBConfig};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::sync::Arc;
use tokio::{
    spawn,
    time::{Duration, sleep},
};
use tokio_util::sync::CancellationToken;

use tempfile::TempDir;

const BRIDGE_0_ADDR: &str = "ws://localhost:26658";

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

async fn setup_nodes() -> (Arc<Prover>, Arc<LightClient>, TempDir) {
    let temp_dir = TempDir::new().expect("Creating a temporary test directory is successful");
    let db_path = temp_dir.path().join("db");

    let prover_key_path = temp_dir.path().join("prover.p8");
    let prover_key = SigningKey::new_ed25519();
    prover_key.to_pkcs8_pem_file(&prover_key_path).expect("Creating prover key file is successful");

    let prover_pubkey = prover_key.verifying_key();
    let prover_pubkey_path = temp_dir.path().join("prover.spki");
    prover_pubkey
        .to_spki_pem_file(&prover_pubkey_path)
        .expect("Creating prover public key file is successful");

    // Create prover
    let prover_cfg = ProverConfig {
        db: DatabaseConfig::RocksDB(RocksDBConfig::new(db_path.to_str().unwrap())),
        da: FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig {
            url: BRIDGE_0_ADDR.to_string(),
            ..CelestiaFullNodeDAConfig::default()
        }),
        signing_key_path: prover_key_path.to_str().unwrap().to_string(),
        start_height: 1,
        max_epochless_gap: 300,
        recursive_proofs: false,
        webserver: WebServerConfig::default(),
    };

    let prover =
        create_prover_as_prover(&prover_cfg).await.expect("Creating prover should be successful");

    // Create light client
    let bootnode = get_bootnode(BRIDGE_0_ADDR).await;

    let lc_cfg = LightClientConfig {
        da: LightClientDAConfig::Celestia(CelestiaLightClientDAConfig {
            celestia_network: CelestiaNetwork::Custom("private".parse().unwrap()),
            bootnodes: vec![bootnode],
            pruning_window: DEFAULT_PRUNING_WINDOW_IN_MEMORY,
            store: CelestiaLightClientDAStoreConfig::InMemory,
            ..CelestiaLightClientDAConfig::default()
        }),
        verifying_key_str: prover_pubkey_path.to_str().unwrap().to_string(),
        allow_mock_proofs: true,
    };

    let lightclient =
        create_light_client(&lc_cfg).await.expect("Creating light client should be successful");

    (Arc::new(prover), Arc::new(lightclient), temp_dir)
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
    let (prover, lightclient, _temp_dir) = setup_nodes().await;

    // Start nodes
    let mut event_sub = prover.start_subscribed().await.expect("Starting prover should work");
    lightclient.start().await.expect("Starting lightclient should work");

    // Start Transaction generation
    let tx_shutdown = CancellationToken::new();
    let prover_clone = Arc::clone(&prover);
    let ct = tx_shutdown.clone();
    let tx_generator = spawn(async move { generate_transactions(prover_clone, ct).await });

    // Grab the latest DA height after subscribing
    let initial_height = loop {
        let event_info = event_sub.recv().await.unwrap();
        if let prism_events::PrismEvent::UpdateDAHeight { height } = event_info.event {
            break height;
        }
    };
    debug!("Initial height: {}", initial_height);

    // Listen for 50 heights
    let target_height = initial_height + 50;
    loop {
        let event_info = event_sub.recv().await.unwrap();
        if let prism_events::PrismEvent::UpdateDAHeight { height } = event_info.event {
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
    assert!(prover.stop().await.is_ok());
    assert!(lightclient.stop().await.is_ok());
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
