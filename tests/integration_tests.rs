use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use keystore_rs::create_signing_key;
use prism::{
    cfg::{Config, RedisConfig},
    common::{AccountSource, Operation},
    da::memory::InMemoryDataAvailabilityLayer,
    node_types::{lightclient::LightClient, sequencer::Sequencer, NodeType},
    storage::{Database, RedisConnection},
    webserver::OperationInput,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{sync::Arc, time::Duration};

fn create_new_account_operation(id: String, value: String, key: &SigningKey) -> OperationInput {
    let incoming = Operation::CreateAccount {
        id: id.clone(),
        value: value.clone(),
        source: AccountSource::SignedBySequencer {
            signature: key.sign(format!("{}{}", id, value).as_bytes()).to_string(),
        },
    };
    let content = serde_json::to_string(&incoming).unwrap();
    let sig = key.sign(content.clone().as_bytes());
    OperationInput {
        operation: incoming,
        signed_operation: sig.to_string(),
        public_key: engine.encode(key.verifying_key().to_bytes()),
    }
}

fn create_update_operation(id: String, value: String) -> OperationInput {
    let key = create_signing_key();
    let incoming = Operation::Add { id, value };
    let content = serde_json::to_string(&incoming).unwrap();
    let sig = key.sign(content.clone().as_bytes());
    OperationInput {
        operation: incoming,
        signed_operation: sig.to_string(),
        public_key: engine.encode(key.verifying_key().to_bytes()),
    }
}

#[tokio::test]
async fn test_light_client_sequencer_talking() {
    std::env::set_var("RUST_LOG", "DEBUG");
    pretty_env_logger::init();

    let (da_layer, mut height_rx, mut _block_rx) = InMemoryDataAvailabilityLayer::new(1);
    let da_layer = Arc::new(da_layer);
    let db = Arc::new(setup_db());
    let cfg = Config::default();
    let signing_key = create_signing_key();
    let pubkey = engine.encode(signing_key.verifying_key().to_bytes());

    let sequencer = Arc::new(
        Sequencer::new(
            db.clone(),
            da_layer.clone(),
            cfg.clone(),
            signing_key.clone(),
        )
        .unwrap(),
    );

    let lightclient = Arc::new(LightClient::new(
        da_layer,
        cfg.celestia_config.unwrap(),
        Some(pubkey),
    ));

    let seq_1 = sequencer.clone();
    tokio::spawn(async move {
        seq_1.start().await.unwrap();
    });

    tokio::spawn(async move {
        lightclient.clone().start().await.unwrap();
    });

    let seq = sequencer.clone();
    tokio::spawn(async move {
        let mut rng = StdRng::from_entropy();
        let mut accounts = Vec::new();
        let mut i = 0;

        loop {
            let seq_clone = seq.clone();
            // Create 1 or 2 new accounts
            let num_new_accounts = rng.gen_range(1..=10);
            for _ in 0..num_new_accounts {
                let seq_i = seq_clone.clone();
                let new_acc = create_new_account_operation(
                    format!("{}@gmail.com", i),
                    format!("key_{}", i),
                    &signing_key,
                );
                seq_i.validate_and_queue_update(&new_acc).await.unwrap();
                accounts.push(format!("{}@gmail.com", i));
                i += 1;
            }

            // Update 5 random existing accounts (if we have at least 5)
            if accounts.len() >= 5 {
                for _ in 0..5 {
                    let seq_i = seq_clone.clone();
                    let account_index = rng.gen_range(0..accounts.len());
                    let account_id = accounts[account_index].clone();
                    let update_op = create_update_operation(
                        account_id,
                        format!("updated_key_{}", rng.gen::<u32>()),
                    );
                    seq_i.validate_and_queue_update(&update_op).await.unwrap();
                }
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    while let Ok(height) = height_rx.recv().await {
        if height == 60 {
            break;
        }
    }

    teardown_db(db.clone())
}

// set up redis connection and flush database before each test
fn setup_db() -> RedisConnection {
    let redis_connection = RedisConnection::new(&RedisConfig::default()).unwrap();
    redis_connection.flush_database().unwrap();
    redis_connection
}

// flush database after each test
fn teardown_db(redis_connections: Arc<RedisConnection>) {
    redis_connections.flush_database().unwrap();
}
