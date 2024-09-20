// #![cfg(test)]

#[macro_use]
extern crate log;

use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey};
use keystore_rs::create_signing_key;
use prism_common::operation::{AccountSource, Operation};
use prism_main::{
    cfg::{CelestiaConfig, Config, RedisConfig},
    da::{celestia::CelestiaConnection, DataAvailabilityLayer},
    node_types::{lightclient::LightClient, sequencer::Sequencer, NodeType},
    storage::{Database, RedisConnection},
    webserver::OperationInput,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::sync::Arc;
use tokio::{spawn, time::Duration};

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
    let pubkey = engine.encode(signing_key.verifying_key().to_bytes());

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

    loop {
        // Create 1 to 10 new accounts
        let num_new_accounts = rng.gen_range(1..=3);
        for _ in 0..num_new_accounts {
            let new_acc = create_new_account_operation(
                format!("{}@gmail.com", i),
                format!("key_{}", i),
                &signing_key,
            );
            sequencer
                .clone()
                .validate_and_queue_update(&new_acc)
                .await
                .unwrap();
            accounts.push(format!("{}@gmail.com", i));
            i += 1;
        }
        let mut rx = lc_da_layer.clone().subscribe_to_heights();
        while let Ok(height) = rx.recv().await {
            debug!("received height {}", height);
            if height == 100 {
                break;
            }
        }
    }
}
