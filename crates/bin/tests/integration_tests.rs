// #![cfg(test)]

#[macro_use]
extern crate log;
use anyhow::Result;
use keystore_rs::create_signing_key;
use prism_bin::{cfg::Config, node_types::NodeType};
use prism_common::{
    operation::{Operation, ServiceChallenge},
    test_utils::create_mock_signing_key,
};
use prism_da::{
    celestia::{CelestiaConfig, CelestiaConnection},
    DataAvailabilityLayer,
};
use prism_lightclient::LightClient;
use prism_prover::Prover;
use prism_storage::{inmemory::InMemoryDatabase, Database};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::sync::Arc;
use tokio::{spawn, time::Duration};

use prism_common::test_utils::{Service, TestTreeState};

fn create_random_user(id: &str, state: &mut TestTreeState, service: &Service) -> Operation {
    let account = state.create_account(id.to_string(), service.clone());
    account.hashchain.last().unwrap().operation.clone()
}

fn add_key(id: &str, state: &mut TestTreeState) -> Result<Operation> {
    let signing_key = state
        .signing_keys
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("Signing key not found for account {}", id))?;

    let new_key = create_mock_signing_key();
    let new_public_key = new_key.verifying_key();

    let op = Operation::new_add_key(
        id.to_string(),
        new_public_key,
        signing_key,
        0, // Assuming this is the key index, you might need to adjust this
    )?;

    Ok(op)
}

fn setup_db() -> Arc<Box<dyn Database>> {
    Arc::new(Box::new(InMemoryDatabase::new()) as Box<dyn Database>)
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
        connection_string: "ws://0.0.0.0:26658".to_string(),
        ..CelestiaConfig::default()
    };

    let bridge_da_layer = Arc::new(CelestiaConnection::new(&bridge_cfg, None).await.unwrap());
    let lc_da_layer = Arc::new(CelestiaConnection::new(&lc_cfg, None).await.unwrap());
    let db = setup_db();
    let cfg = Config::default();
    let signing_key = create_signing_key();
    let pubkey = signing_key.verification_key();

    let mut test_state = TestTreeState::new();
    let _service = test_state.register_service("test_service".to_string());

    let prover = Arc::new(Prover::new(
        db.clone(),
        bridge_da_layer.clone(),
        cfg.clone().webserver.unwrap(),
        cfg.clone().celestia_config.unwrap().start_height,
        signing_key.clone(),
    )?);

    let lightclient = Arc::new(LightClient::new(
        lc_da_layer.clone(),
        cfg.celestia_config.unwrap(),
        Some(pubkey),
    ));

    let prover_clone = prover.clone();
    spawn(async move {
        debug!("starting prover");
        prover_clone.start().await.unwrap();
    });

    let lc_clone = lightclient.clone();
    spawn(async move {
        debug!("starting light client");
        lc_clone.start().await.unwrap();
    });

    spawn(async move {
        let mut rng = StdRng::from_entropy();
        let mut test_state = TestTreeState::new();
        let service = test_state.register_service("test_service".to_string());
        let op = Operation::new_register_service(
            service.clone().id,
            ServiceChallenge::Signed(service.clone().vk),
        );
        let mut i = 0;

        prover.clone().validate_and_queue_update(&op).await.unwrap();

        loop {
            // Create 1 to 3 new accounts
            let num_new_accounts = rng.gen_range(1..=3);
            for _ in 0..num_new_accounts {
                let new_acc = create_random_user(
                    format!("{}@gmail.com", i).as_str(),
                    &mut test_state,
                    &service,
                );
                match prover.clone().validate_and_queue_update(&new_acc).await {
                    Ok(_) => i += 1,
                    Err(e) => eprintln!("Failed to create account: {}", e),
                }
            }

            // Update 5 random existing accounts (if we have at least 5)
            if test_state.signing_keys.len() >= 5 {
                for _ in 0..5 {
                    let account_id = match test_state
                        .signing_keys
                        .keys()
                        .nth(rng.gen_range(0..test_state.signing_keys.len()))
                    {
                        Some(id) => id.clone(),
                        None => {
                            eprintln!("Failed to get random account id");
                            continue;
                        }
                    };
                    match add_key(&account_id, &mut test_state) {
                        Ok(update_op) => {
                            if let Err(e) =
                                prover.clone().validate_and_queue_update(&update_op).await
                            {
                                eprintln!("Failed to validate and queue update: {}", e);
                            }
                        }
                        Err(e) => eprintln!("Failed to add key: {}", e),
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    let mut rx = lc_da_layer.clone().subscribe_to_heights();
    while let Ok(height) = rx.recv().await {
        debug!("received height {}", height);
        if height >= 100 {
            break;
        }
    }

    Ok(())
}
