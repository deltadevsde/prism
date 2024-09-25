// #![cfg(test)]

#[macro_use]
extern crate log;

use anyhow::Result;
use ed25519_dalek::SigningKey;
use keystore_rs::create_signing_key;
use prism_common::operation::{
    CreateAccountArgs, KeyOperationArgs, Operation, PublicKey, ServiceChallengeInput,
    SignatureBundle,
};
use prism_main::{
    cfg::{CelestiaConfig, Config, RedisConfig},
    da::{celestia::CelestiaConnection, DataAvailabilityLayer},
    node_types::{lightclient::LightClient, sequencer::Sequencer, NodeType},
    storage::{Database, RedisConnection},
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{collections::HashMap, sync::Arc};
use tokio::{spawn, time::Duration};

fn create_random_user(id: &str, signing_key: SigningKey) -> Operation {
    let mut op = Operation::CreateAccount(CreateAccountArgs {
        id: id.to_string(),
        value: PublicKey::Ed25519(signing_key.verifying_key().to_bytes().to_vec()),
        service_id: "test_service".to_string(),
        signature: Vec::new(),
        challenge: ServiceChallengeInput::Signed(vec![]),
    });

    op.insert_signature(&signing_key)
        .expect("Inserting signature into operation should succeed");
    op
}

fn add_key(id: &str, key_idx: u64, new_key: PublicKey, signing_key: SigningKey) -> Operation {
    let mut op = Operation::AddKey(KeyOperationArgs {
        id: id.to_string(),
        value: new_key.clone(),
        signature: SignatureBundle {
            key_idx,
            signature: Vec::new(),
        },
    });

    op.insert_signature(&signing_key)
        .expect("Inserting signature into operation should succeed");
    op
}

fn setup_db() -> Arc<Box<dyn Database>> {
    let redis_connection = RedisConnection::new(&RedisConfig::default()).unwrap();
    Arc::new(Box::new(redis_connection) as Box<dyn Database>)
}

#[tokio::test]
async fn test_light_client_sequencer_talking() -> Result<()> {
    std::env::set_var(
        "RUST_LOG",
        "DEBUG,tracing=off,sp1_stark=info,p3_dft=off,p3_fri=off,sp1_core_executor=info,sp1_recursion_program=info,p3_merkle_tree=off,sp1_recursion_compiler=off,sp1_core_machine=off",
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
    let pubkey = signing_key.verifying_key();

    let sequencer = Arc::new(Sequencer::new(
        db.clone(),
        bridge_da_layer.clone(),
        cfg.clone(),
        signing_key.clone(),
    )?);

    let lightclient = Arc::new(LightClient::new(
        lc_da_layer.clone(),
        cfg.celestia_config.unwrap(),
        Some(pubkey),
    ));

    let seq_clone = sequencer.clone();
    spawn(async move {
        debug!("starting sequencer");
        seq_clone.start().await.unwrap();
    });

    let lc_clone = lightclient.clone();
    spawn(async move {
        debug!("starting light client");
        lc_clone.start().await.unwrap();
    });

    spawn(async move {
        let mut rng = StdRng::from_entropy();
        let mut accounts: HashMap<String, Vec<SigningKey>> = HashMap::new();
        let mut i = 0;

        loop {
            // Create 1 to 3 new accounts
            let num_new_accounts = rng.gen_range(1..=3);
            for _ in 0..num_new_accounts {
                let new_key = create_signing_key();
                let new_acc =
                    create_random_user(format!("{}@gmail.com", i).as_str(), new_key.clone());
                sequencer
                    .clone()
                    .validate_and_queue_update(&new_acc)
                    .await
                    .unwrap();
                accounts
                    .insert(format!("{}@gmail.com", i), vec![new_key])
                    .unwrap();
                i += 1;
            }

            // Update 5 random existing accounts (if we have at least 5)
            if accounts.len() >= 5 {
                for _ in 0..5 {
                    let account_id = accounts
                        .keys()
                        .nth(rng.gen_range(0..accounts.len()))
                        .unwrap();
                    let signing_keys = accounts.get(account_id).unwrap();
                    let signing_key = signing_keys.last().unwrap();
                    let new_key = create_signing_key();
                    let new_public_key =
                        PublicKey::Ed25519(new_key.verifying_key().to_bytes().to_vec());
                    let update_op = add_key(
                        account_id,
                        (signing_keys.len() - 1) as u64,
                        new_public_key,
                        signing_key.clone(),
                    );
                    sequencer
                        .clone()
                        .validate_and_queue_update(&update_op)
                        .await
                        .unwrap();
                }
            }

            tokio::time::sleep(Duration::from_millis(5000)).await;
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
