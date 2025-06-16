mod cfg;
mod node_types;

use cfg::{
    Cli, Commands, initialize_da_layer, initialize_db, initialize_light_da_layer, load_config,
};
use clap::Parser;
use keystore_rs::{FileStore, KeyChain, KeyStore};
use prism_keys::{CryptoAlgorithm, SigningKey};
use prism_serde::base64::ToBase64;
use prism_telemetry::telemetry::shutdown_telemetry;
use prism_telemetry_registry::{init::init, metrics_registry::get_metrics};

use std::io::{Error, ErrorKind};

use node_types::NodeType;
use prism_lightclient::LightClient;
use prism_prover::Prover;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub const SIGNING_KEY_ID: &str = "prism";

/// The main function that initializes and runs a prism client.
#[tokio::main()]
/// Initializes and runs the appropriate prism node type based on CLI arguments.
///
/// Parses command-line arguments, loads configuration, sets up telemetry, initializes key management and data availability layers, and starts the selected node type (`LightClient`, `Prover`, or `FullNode`). Handles errors during setup and ensures telemetry is properly shut down after execution.
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
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Missing telemetry configuration",
            ));
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

    let attributes: Vec<(String, String)> = vec![
        ("network".to_string(), config.network.network.to_string()),
        ("node_type".to_string(), node_type.clone()),
    ];
    let (meter_provider, log_provider) = init(telemetry_config.clone(), attributes)?;

    let celestia_config = config.network.celestia_config.clone().unwrap_or_default();
    let start_height = celestia_config.start_height;
    let cancellation_token = CancellationToken::new();

    // Use the metrics registry to record metrics
    if let Some(metrics) = get_metrics() {
        metrics.record_node_info(vec![
            ("version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
            (
                "operation_namespace_id".to_string(),
                celestia_config.operation_namespace_id.to_string(),
            ),
            (
                "snark_namespace_id".to_string(),
                celestia_config.snark_namespace_id.to_string(),
            ),
            ("start_height".to_string(), start_height.to_string()),
        ]);
    }

    let node: Arc<dyn NodeType> = match cli.command {
        Commands::LightClient(_) => {
            let verifying_key = config.network.verifying_key.clone();

            let da = initialize_light_da_layer(&config).await.map_err(|e| {
                error!("error initializing light da layer: {}", e);
                Error::other(e.to_string())
            })?;

            Arc::new(LightClient::new(da, verifying_key))
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

            // When SP1_PROVER is set to mock, disable recursive proofs
            let recursive_proofs = std::env::var("SP1_PROVER").map_or(true, |val| val != "mock");
            let prover_cfg = prism_prover::Config {
                syncer: prism_prover::SyncerConfig {
                    verifying_key,
                    start_height,
                    max_epochless_gap: config.max_epochless_gap,
                    prover_enabled: true,
                },
                sequencer: prism_prover::SequencerConfig {
                    signing_key,
                    batcher_enabled: true,
                },
                prover_engine: prism_prover::ProverEngineConfig { recursive_proofs },
                webserver: webserver_config.clone().unwrap_or_default(),
            };

            Arc::new(
                Prover::new(db, da, &prover_cfg, cancellation_token.clone()).map_err(|e| {
                    error!("error initializing prover: {}", e);
                    Error::other(e.to_string())
                })?,
            )
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

            let verifying_key = config.network.verifying_key.clone();

            // When SP1_PROVER is set to mock, disable recursive proofs
            let recursive_proofs = std::env::var("SP1_PROVER").map_or(true, |val| val != "mock");
            let prover_cfg = prism_prover::Config {
                syncer: prism_prover::SyncerConfig {
                    verifying_key,
                    start_height,
                    max_epochless_gap: config.max_epochless_gap,
                    prover_enabled: false, // FullNode doesn't generate proofs
                },
                sequencer: prism_prover::SequencerConfig {
                    signing_key,
                    batcher_enabled: true,
                },
                prover_engine: prism_prover::ProverEngineConfig { recursive_proofs },
                webserver: webserver_config.unwrap_or_default(),
            };

            Arc::new(
                Prover::new(db, da, &prover_cfg, cancellation_token.clone()).map_err(|e| {
                    error!("error initializing prover: {}", e);
                    Error::other(e.to_string())
                })?,
            )
        }
    };

    // Setup signal handling for graceful shutdown
    let cancellation_for_signal = cancellation_token.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigint =
            signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown");
            },
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
            }
        }

        cancellation_for_signal.cancel();
    });

    let result = node.start().await.map_err(|e| Error::other(e.to_string()));

    shutdown_telemetry(telemetry_config, meter_provider, log_provider);

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
