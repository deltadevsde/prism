#![cfg(test)]

#[macro_use]
extern crate log;

use anyhow::Result;
use keystore_rs::create_signing_key;
use prism_common::transaction_builder::TransactionBuilder;
use prism_da::{
    celestia::{CelestiaConfig, CelestiaConnection},
    DataAvailabilityLayer,
};
use prism_lightclient::LightClient;
use prism_prover::Prover;
use prism_storage::{rocksdb::RocksDBConnection, Database};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::sync::Arc;
use tokio::{spawn, time::Duration};

use tempfile::TempDir;

fn setup_db() -> Arc<Box<dyn Database>> {
    let temp_dir = TempDir::new().unwrap();
    let db = RocksDBConnection::new(temp_dir.path().to_str().unwrap()).unwrap();
    Arc::new(Box::new(db) as Box<dyn Database>)
}

#[tokio::test]
async fn test_light_client_prover_talking() -> Result<()> {
    std::env::set_var(
        "RUST_LOG",
        "DEBUG,tracing=off,sp1_stark=info,jmt=off,p3_dft=off,p3_fri=off,sp1_core_executor=info,sp1_recursion_program=info,p3_merkle_tree=off,sp1_recursion_compiler=off,sp1_core_machine=off",
    );
    pretty_env_logger::init();

    let bridge_cfg = CelestiaConfig {
        connection_string: "ws://0.0.0.0:36658".to_string(),
        ..CelestiaConfig::default()
    };
    let lc_cfg = CelestiaConfig {
        connection_string: "ws://0.0.0.0:46658".to_string(),
        ..CelestiaConfig::default()
    };

    let bridge_da_layer = Arc::new(CelestiaConnection::new(&bridge_cfg, None).await.unwrap());
    let lc_da_layer = Arc::new(CelestiaConnection::new(&lc_cfg, None).await.unwrap());
    let db = setup_db();
    let signing_key = create_signing_key();
    let pubkey = signing_key.verification_key();

    let prover_cfg = prism_prover::Config {
        signing_key,
        ..prism_prover::Config::default()
    };

    let prover = Arc::new(Prover::new(
        db.clone(),
        bridge_da_layer.clone(),
        &prover_cfg,
    )?);

    let lightclient = Arc::new(LightClient::new(lc_da_layer.clone(), lc_cfg, Some(pubkey)));

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
        let mut rng = StdRng::from_entropy();

        let mut transaction_builder = TransactionBuilder::new();
        let register_service_req =
            transaction_builder.register_service_with_random_keys("test_service").commit();

        let mut i = 0;

        prover.clone().validate_and_queue_update(register_service_req).await.unwrap();
        let mut added_account_ids: Vec<String> = Vec::new();

        loop {
            // Create 1 to 3 new accounts
            let num_new_accounts = rng.gen_range(1..=3);
            for _ in 0..num_new_accounts {
                let random_user_id = format!("{}@gmail.com", i);
                let new_acc = transaction_builder
                    .create_account_with_random_key_signed(random_user_id.as_str(), "test_service")
                    .commit();
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

                    let update_acc =
                        transaction_builder.add_random_key_verified_with_root(acc_id).commit();

                    match prover.clone().validate_and_queue_update(update_acc).await {
                        Ok(_) => (),
                        Err(e) => eprintln!("Failed to validate and queue update: {}", e),
                    };
                }
            }

            tokio::time::sleep(Duration::from_millis(5000)).await;
        }
    });

    let mut rx = lc_da_layer.clone().subscribe_to_heights();
    let initial_height = rx.recv().await.unwrap();
    while let Ok(height) = rx.recv().await {
        debug!("received height {}", height);
        if height >= initial_height + 100 {
            break;
        }
    }

    Ok(())
}
