mod cfg;
mod node_types;

use cfg::{
    Cli, Commands, initialize_da_layer, initialize_db, initialize_light_da_layer, load_config,
};
use clap::Parser;
use keystore_rs::{FileStore, KeyChain, KeyStore};
use opentelemetry::{global::{self}, KeyValue};
use prism_keys::{CryptoAlgorithm, SigningKey};
use prism_serde::base64::ToBase64;
use prism_telemetry_registry::metrics_registry::{init_metrics_registry, get_metrics};
use prism_telemetry::telemetry::{self, build_resource, init_telemetry, set_global_attributes};
use prism_telemetry::logs::setup_log_subscriber;

use std::io::{Error, ErrorKind};

use node_types::NodeType;
use prism_lightclient::{LightClient, events::EventChannel};
use prism_prover::Prover;
use std::sync::Arc;
use tracing::{info, error};

pub const SIGNING_KEY_ID: &str = "prism";

/// The main function that initializes and runs a prism client.
#[tokio::main()]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let args = match cli.clone().command {
        Commands::LightClient(args) | Commands::Prover(args) | Commands::FullNode(args) => args,
    };

    let config = load_config(args.clone()).map_err(|e| Error::other(e.to_string()))?;

    // Extract and clone all fields that will be moved
    let telemetry_config = match config.telemetry.clone() {
        Some(cfg) => cfg,
        None => {
            return Err(Error::new(ErrorKind::InvalidInput, "Missing telemetry configuration"));
        }
    };
    let keystore_type = config.keystore_type.clone();
    let keystore_path = config.keystore_path.clone();
    let webserver_config = config.webserver.clone();

    let node_type = match cli.command {
        Commands::LightClient(_) => "lightclient".to_string(),
        Commands::Prover(_) => "prover".to_string(),
        Commands::FullNode(_) => "fullnode".to_string(),
    };

    let mut attributes: Vec<KeyValue> = Vec::new();
    attributes.extend(telemetry_config.global_labels.labels.clone().into_iter().map(|(k, v)| KeyValue::new(k, v)));
    attributes.push(KeyValue::new("network".to_string(), config.network.network.to_string()));
    attributes.push(KeyValue::new("node_type".to_string(), node_type));

    set_global_attributes(attributes.clone());

    let resource = build_resource("prism".to_string(), attributes);

    let (meter_provider, log_provider) = init_telemetry(&telemetry_config, resource).map_err(|e| Error::other(e.to_string()))?;

    if let Some(ref provider) = meter_provider {
        global::set_meter_provider(provider.clone());

        // Initialize the metrics registry after setting the global meter provider
        init_metrics_registry();
    }

    if let Some(ref provider) = log_provider {
        // Initialize tracing subscriber
        setup_log_subscriber(
            telemetry_config.logs.enabled,
            Some(provider)
        );
    }

    let celestia_config = config.network.celestia_config.clone().unwrap_or_default();
    let start_height = celestia_config.start_height;

    // Use the metrics registry to record metrics
    if let Some(metrics) = get_metrics() {
        metrics.record_node_info(
            vec![
                ("version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
                ("operation_namespace_id".to_string(), celestia_config.operation_namespace_id.to_string()),
                ("snark_namespace_id".to_string(), celestia_config.snark_namespace_id.to_string()),
                ("start_height".to_string(), start_height.to_string()),
            ]
        );
    }

    let node: Arc<dyn NodeType> = match cli.command {
        Commands::LightClient(_) => {
            let verifying_key = config.network.verifying_key.clone();

            let da = initialize_light_da_layer(&config).await.map_err(|e| {
                error!("error initializing light da layer: {}", e);
                Error::other(e.to_string())
            })?;

            let event_channel = EventChannel::new();

            Arc::new(LightClient::new(
                da,
                start_height,
                verifying_key,
                event_channel.publisher(),
            ))
        }
        Commands::Prover(_) => {
            let db = initialize_db(&config).map_err(|e| Error::other(e.to_string()))?;

            let da = initialize_da_layer(&config).await.map_err(|e| Error::other(e.to_string()))?;
            info!(
                "keystore type: {:?}",
                keystore_type.clone().unwrap_or_default()
            );

            info!("SP1_PROVER: {:?}", std::env::var("SP1_PROVER"));

            let signing_key = get_signing_key(keystore_type.clone(), keystore_path.clone())?;
            let verifying_key = signing_key.verifying_key();

            info!(
                "prover's verifying key: {}",
                verifying_key.to_bytes().to_base64()
            );

            let prover_cfg = prism_prover::Config {
                prover: true,
                batcher: true,
                webserver: webserver_config.clone().unwrap_or_default(),
                signing_key,
                verifying_key,
                start_height,
            };

            Arc::new(Prover::new(db, da, &prover_cfg).map_err(|e| {
                error!("error initializing prover: {}", e);
                Error::other(e.to_string())
            })?)
        }
        Commands::FullNode(_) => {
            let db = initialize_db(&config).map_err(|e| Error::other(e.to_string()))?;

            let da = initialize_da_layer(&config).await.map_err(|e| Error::other(e.to_string()))?;

            info!(
                "keystore type: {:?}",
                keystore_type.clone().unwrap_or_default()
            );

            info!("SP1_PROVER: {:?}", std::env::var("SP1_PROVER"));

            let signing_key = get_signing_key(keystore_type, keystore_path)?;

            let verifying_key = config
                .network
                .verifying_key
                .clone()
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "prover verifying key not found"))?;

            let prover_cfg = prism_prover::Config {
                prover: false,
                batcher: true,
                webserver: webserver_config.unwrap_or_default(),
                signing_key,
                verifying_key,
                start_height,
            };

            Arc::new(Prover::new(db, da, &prover_cfg).map_err(|e| {
                error!("error initializing prover: {}", e);
                Error::other(e.to_string())
            })?)
        }
    };

    let result = node.start().await.map_err(|e| Error::other(e.to_string()));

    telemetry::shutdown_telemetry(telemetry_config, meter_provider, log_provider);

    result
}

fn get_signing_key(
    keystore_type: Option<String>,
    keystore_path: Option<String>,
) -> std::io::Result<SigningKey> {
    let keystore: Box<dyn KeyStore> = match keystore_type.unwrap_or_default().as_str() {
        "file" => {
            let file_store = FileStore::new(keystore_path.unwrap_or_default())
                .map_err(|e| Error::other(e.to_string()))?;
            Box::new(file_store)
        }
        "keychain" => Box::new(KeyChain),
        _ => {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid keystore type"));
        }
    };

    let raw_signing_key = keystore
        .get_or_create_signing_key(SIGNING_KEY_ID)
        .map_err(|e| Error::other(format!("Failed to get or create signing key: {}", e)))?;

    // Hardcoded ED25519 as keystore_rs only supports ED25519
    let signing_key =
        SigningKey::from_algorithm_and_bytes(CryptoAlgorithm::Ed25519, raw_signing_key.as_bytes())
            .map_err(|e| Error::other(format!("Failed to parse signing key: {}", e)))?;

    Ok(signing_key)
}
