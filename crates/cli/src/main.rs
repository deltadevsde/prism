mod apply_args;
mod cli_args;
mod config;
mod node_types;

use clap::Parser;
use node_types::NodeType;
use prism_cli::error::CliError;
use prism_da::{create_full_node_da_layer, create_light_client_da_layer};
use prism_lightclient::create_light_client;
use prism_prover::factory::{create_prover_as_full_node, create_prover_as_prover};
use prism_storage::create_storage;
use prism_telemetry_registry::create_telemetry;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    apply_args::CliOverridableConfig,
    cli_args::{Cli, CliCommands},
    config::{CliFullNodeConfig, CliLightClientConfig, CliProverConfig},
};

/// The main function that initializes and runs a prism client.
#[tokio::main()]
async fn main() {
    if let Err(e) = run_cli().await {
        // TODO Using eprintln directly can probably be avoided when telemetry crate allows to set
        // tracing subscriber earlier
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Initializes and runs the appropriate prism node type based on CLI arguments.
///
/// Parses command-line arguments, loads configuration, sets up telemetry, initializes key
/// management and data availability layers, and starts the selected node type (`LightClient`,
/// `Prover`, or `FullNode`). Handles errors during setup and ensures telemetry is properly shut
/// down after execution.
async fn run_cli() -> Result<(), CliError> {
    let cli = Cli::parse();

    // Setup cancellation token for graceful shutdown
    let cancellation_token = CancellationToken::new();
    let cancellation_for_signal = cancellation_token.clone();

    let (node, telemetry) = match cli.command {
        CliCommands::LightClient(ref light_client_args) => {
            let config = CliLightClientConfig::load(light_client_args).map_err(|e| {
                CliError::ConfigFailed(format!("Error loading light client config: {}", e))
            })?;

            let da = create_light_client_da_layer(&config.da).await?;
            let telemetry = create_telemetry(
                &config.telemetry,
                vec![("node_type".to_string(), "lightclient".to_string())],
            )?;

            let light_client =
                create_light_client(da, &config.light_client, cancellation_token.clone()).map_err(
                    |e| CliError::ConfigFailed(format!("Failed to create light client: {}", e)),
                )?;
            // Arc::new(light_client)
            (Arc::new(light_client) as Arc<dyn NodeType>, telemetry)
        }
        CliCommands::Prover(ref prover_args) => {
            let config = CliProverConfig::load(prover_args).map_err(|e| {
                CliError::ConfigFailed(format!("Error loading prover config: {}", e))
            })?;

            let db = create_storage(&config.db).await?;
            let da = create_full_node_da_layer(&config.da).await?;
            let telemetry = create_telemetry(
                &config.telemetry,
                vec![("node_type".to_string(), "prover".to_string())],
            )?;

            let prover = create_prover_as_prover(
                &config.prover,
                db.clone(),
                da.clone(),
                cancellation_token.clone(),
            )
            .map_err(|e| CliError::ConfigFailed(format!("Failed to create prover: {}", e)))?;

            (Arc::new(prover) as Arc<dyn NodeType>, telemetry)
        }
        CliCommands::FullNode(ref full_node_args) => {
            let config = CliFullNodeConfig::load(full_node_args).map_err(|e| {
                CliError::ConfigFailed(format!("Error loading full node config: {}", e))
            })?;

            let db = create_storage(&config.db).await?;
            let da = create_full_node_da_layer(&config.da).await?;
            let telemetry = create_telemetry(
                &config.telemetry,
                vec![("node_type".to_string(), "fullnode".to_string())],
            )?;

            let full_node = create_prover_as_full_node(
                &config.full_node,
                db.clone(),
                da.clone(),
                cancellation_token.clone(),
            )
            .map_err(|e| CliError::ConfigFailed(format!("Failed to create full node: {}", e)))?;

            // Arc::new(full_node)
            (Arc::new(full_node) as Arc<dyn NodeType>, telemetry)
        }
    };

    // Setup signal handling for graceful shutdown
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

    telemetry.shutdown();

    result.map_err(|e| {
        // Log the error with full debug information
        tracing::error!("Node encountered an error: {:?}", e);
        // Return the error
        CliError::NodeError(format!("{:?}", e))
    })
}
