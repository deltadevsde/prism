#![cfg(test)]

#[macro_use]
extern crate log;

use anyhow::Result;
use prism_common::test_transaction_builder::TestTransactionBuilder;
use prism_da::{
    celestia::{full_node::CelestiaConnection, utils::CelestiaConfig},
    DataAvailabilityLayer,
};
use prism_keys::{CryptoAlgorithm, SigningKey};
use prism_lightclient::{events::EventChannel, LightClient};
use prism_prover::Prover;
use prism_storage::{
    rocksdb::{RocksDBConfig, RocksDBConnection},
    Database,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sp1_sdk::{HashableKey, Prover as _, ProverClient};
use std::sync::Arc;
use tokio::{spawn, time::Duration};

use tempfile::TempDir;

pub const PRISM_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

fn setup_db() -> Arc<Box<dyn Database>> {
    let temp_dir = TempDir::new().unwrap();
    let cfg = RocksDBConfig::new(temp_dir.path().to_str().unwrap());
    let db = RocksDBConnection::new(&cfg).unwrap();
    Arc::new(Box::new(db) as Box<dyn Database>)
}

#[tokio::test]
async fn test_light_client_prover_talking() -> Result<()> {
    std::env::set_var(
        "RUST_LOG",
        "DEBUG,tracing=off,sp1_stark=info,jmt=off,p3_dft=off,p3_fri=off,sp1_core_executor=info,sp1_recursion_program=info,p3_merkle_tree=off,sp1_recursion_compiler=off,sp1_core_machine=off",
    );
    pretty_env_logger::init();

    let prover_client = ProverClient::builder().mock().build();

    let (_, vk) = prover_client.setup(PRISM_ELF);

    let bridge_cfg = CelestiaConfig {
        connection_string: "ws://localhost:26658".to_string(),
        ..CelestiaConfig::default()
    };
    let lc_cfg = CelestiaConfig {
        connection_string: "ws://localhost:46658".to_string(),
        ..CelestiaConfig::default()
    };

    let mut rng = StdRng::from_entropy();
    let prover_algorithm = CryptoAlgorithm::Ed25519;
    let service_algorithm = random_algorithm(&mut rng);

    let bridge_da_layer = Arc::new(CelestiaConnection::new(&bridge_cfg, None).await.unwrap());
    let lc_da_layer = Arc::new(CelestiaConnection::new(&lc_cfg, None).await.unwrap());
    let db = setup_db();
    let signing_key = SigningKey::new_with_algorithm(prover_algorithm)
        .map_err(|e| anyhow::anyhow!("Failed to generate signing key: {}", e))?;
    let pubkey = signing_key.verifying_key();

    let prover_cfg = prism_prover::Config {
        signing_key,
        ..prism_prover::Config::default()
    };

    let prover = Arc::new(Prover::new(
        db.clone(),
        bridge_da_layer.clone(),
        &prover_cfg,
    )?);

    let event_channel = EventChannel::new();

    let lightclient = Arc::new(LightClient::new(
        lc_da_layer.clone(),
        lc_cfg.start_height,
        Some(pubkey),
        vk.bytes32(),
        event_channel.publisher(),
    ));

    let prover_clone = prover.clone();
    spawn(async move {
        debug!("starting prover");
        prover_clone.run().await.unwrap();
    });

    let lc_clone = lightclient.clone();
    spawn(async move {
        debug!("starting light client");
        lc_clone.run().await.unwrap();
    });

    spawn(async move {
        let mut transaction_builder = TestTransactionBuilder::new();
        let register_service_req = transaction_builder
            .register_service_with_random_keys(service_algorithm, "test_service")
            .commit();

        let mut i = 0;

        prover.clone().validate_and_queue_update(register_service_req).await.unwrap();
        let mut added_account_ids: Vec<String> = Vec::new();

        loop {
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

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let mut rx = lc_da_layer.clone().subscribe_to_heights();
    let initial_height = rx.recv().await.unwrap();
    while let Ok(height) = rx.recv().await {
        debug!("received height {}", height);
        if height >= initial_height + 50 {
            break;
        }
    }

    Ok(())
}

fn random_algorithm(rng: &mut StdRng) -> CryptoAlgorithm {
    [
        CryptoAlgorithm::Ed25519,
        CryptoAlgorithm::Secp256k1,
        CryptoAlgorithm::Secp256r1,
    ][rng.gen_range(0..3)]
}
