mod cfg;
mod cli_args;
mod node_types;

use cfg::load_config;
use clap::Parser;
use node_types::NodeType;
use prism_cli::{cfg::ProverConfig, error::CliError};
use prism_da::{create_full_node_da_layer, create_light_client_da_layer};
use prism_lightclient::{LightClient, create_light_client};
use prism_prover::factory::{create_prover_as_full_node, create_prover_as_prover};

use prism_storage::create_storage;
use prism_telemetry::telemetry::shutdown_telemetry;
use prism_telemetry_registry::{init::init, metrics_registry::get_metrics};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    cfg::{FullNodeConfig, LightClientConfig},
    cli_args::{Cli, CliCommands},
};

pub const SIGNING_KEY_ID: &str = "prism";

/// The main function that initializes and runs a prism client.
#[tokio::main()]
/// Initializes and runs the appropriate prism node type based on CLI arguments.
///
/// Parses command-line arguments, loads configuration, sets up telemetry, initializes key
/// management and data availability layers, and starts the selected node type (`LightClient`,
/// `Prover`, or `FullNode`). Handles errors during setup and ensures telemetry is properly shut
/// down after execution.
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    let args = match cli.clone().command {
        CliCommands::LightClient(args)
        | CliCommands::Prover(args)
        | CliCommands::FullNode(args) => args,
    };

    // TODO: use command specific converters and check whether this can be moved down
    let config = load_config(args.clone())
        .map_err(|e| CliError::ConfigFailed(format!("Error loading config: {}", e)))?;

    // Extract and clone all fields that will be moved
    let telemetry_config = match config.telemetry.clone() {
        Some(cfg) => cfg,
        None => {
            return Err(CliError::ConfigFailed(
                "Could not load telemetry config".to_string(),
            ));
        }
    };
    let _keystore_type = config.keystore_type.clone();
    let _keystore_path = config.keystore_path.clone();
    let _webserver_config = config.webserver.clone();

    let node_type = match cli.command {
        CliCommands::LightClient(_) => "lightclient".to_string(),
        CliCommands::Prover(_) => "prover".to_string(),
        CliCommands::FullNode(_) => "fullnode".to_string(),
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
        CliCommands::LightClient(_light_client_args) => {
            // TODO: light_client_args -> light_client_config / config
            // TODO: Replace using the default below
            let config = LightClientConfig::default().custom_config();
            let verifying_key = config.verifying_key.clone();

            let da = create_light_client_da_layer(&config.da).await?;

            let light_client = create_light_client(da, verifying_key, cancellation_token.clone())
                .map_err(|e| {
                CliError::ConfigFailed(format!("Failed to create light client: {}", e))
            })?;
            Arc::new(light_client)
        }
        CliCommands::Prover(_) => {
            // TODO: light_client_args -> light_client_config / config
            // TODO: Replace using the default below
            let config = ProverConfig::default().custom_config();

            let db = create_storage(&config.db).await?;
            let da = create_full_node_da_layer(&config.da).await?;
            let prover = create_prover_as_prover(
                &config.prover,
                db.clone(),
                da.clone(),
                cancellation_token.clone(),
            )
            .map_err(|e| CliError::ConfigFailed(format!("Failed to create prover: {}", e)))?;

            Arc::new(prover)
        }
        CliCommands::FullNode(_) => {
            // TODO: light_client_args -> light_client_config / config
            // TODO: Replace using the default below
            let config = FullNodeConfig::default().custom_config();

            // let db = initialize_db(&config).map_err(|e| Error::other(e.to_string()))?;
            let db = create_storage(&config.db).await?;
            let da = create_full_node_da_layer(&config.da).await?;
            let full_node = create_prover_as_full_node(
                &config.full_node,
                db.clone(),
                da.clone(),
                cancellation_token.clone(),
            )
            .map_err(|e| CliError::ConfigFailed(format!("Failed to create full node: {}", e)))?;

            Arc::new(full_node)
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

    let result = node.start().await;

    shutdown_telemetry(telemetry_config, meter_provider, log_provider);

    result.map_err(|e| {
        // Log the error with full debug information
        tracing::error!("Node encountered an error: {:?}", e);
        // Return the error
        CliError::NodeError(format!("{:?}", e))
    })
}
