mod apply_args;
mod cli_args;
mod config;
mod file_utils;
mod node_types;

use clap::Parser;
use dotenvy::dotenv;
use node_types::NodeType;
use prism_cli::error::CliError;
use prism_da::{create_full_node_da_layer, create_light_client_da_layer};
use prism_lightclient::create_light_client;
use prism_prover::{create_prover_as_full_node, create_prover_as_prover};
use prism_storage::create_storage;
use prism_telemetry_registry::{TelemetryInstance, create_telemetry};
use std::sync::Arc;
use tokio::signal;
use tracing::info;

use crate::{
    apply_args::CliOverridableConfig,
    cli_args::{Cli, CliCommands, FullNodeCliArgs, LightClientCliArgs, ProverCliArgs},
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
    // Load potential .env file into environment, before parsing cli/config
    dotenv().ok();

    let cli = Cli::parse();

    let (node, telemetry) = match cli.command {
        CliCommands::LightClient(ref light_client_args) => {
            create_light_node(light_client_args).await?
        }
        CliCommands::Prover(ref prover_args) => create_prover_node(prover_args).await?,
        CliCommands::FullNode(ref full_node_args) => create_full_node(full_node_args).await?,
    };

    node.start().await.map_err(|e| {
        // Log the error with full debug information
        tracing::error!("Node encountered an error: {:?}", e);
        // Return the error
        CliError::NodeError(format!("{:?}", e))
    })?;

    // Wait for shutdown signal
    shutdown_signal().await;

    let stop_result = node.stop().await.map_err(|e| {
        // Log the error with full debug information
        tracing::error!("Node encountered an error: {:?}", e);
        // Return the error
        CliError::NodeError(format!("{:?}", e))
    });
    telemetry.shutdown();

    stop_result
}

async fn create_light_node(
    light_client_args: &LightClientCliArgs,
) -> Result<(Arc<dyn NodeType>, TelemetryInstance), CliError> {
    let config = CliLightClientConfig::load(light_client_args)
        .map_err(|e| CliError::ConfigFailed(format!("Error loading light client config: {}", e)))?;

    let telemetry = create_telemetry(
        &config.telemetry,
        vec![("node_type".to_string(), "lightclient".to_string())],
    )?;

    let da = create_light_client_da_layer(&config.da).await?;

    let light_client = create_light_client(da, &config.light_client)
        .map_err(|e| CliError::ConfigFailed(format!("Failed to create light client: {}", e)))?;
    Ok((Arc::new(light_client) as Arc<dyn NodeType>, telemetry))
}

async fn create_prover_node(
    prover_args: &ProverCliArgs,
) -> Result<(Arc<dyn NodeType>, TelemetryInstance), CliError> {
    let config = CliProverConfig::load(prover_args)
        .map_err(|e| CliError::ConfigFailed(format!("Error loading prover config: {}", e)))?;

    let telemetry = create_telemetry(
        &config.telemetry,
        vec![("node_type".to_string(), "prover".to_string())],
    )?;

    let db = create_storage(&config.db).await?;
    let da = create_full_node_da_layer(&config.da).await?;

    let prover = create_prover_as_prover(&config.prover, db.clone(), da.clone())
        .map_err(|e| CliError::ConfigFailed(format!("Failed to create prover: {}", e)))?;

    Ok((Arc::new(prover) as Arc<dyn NodeType>, telemetry))
}

async fn create_full_node(
    full_node_args: &FullNodeCliArgs,
) -> Result<(Arc<dyn NodeType>, TelemetryInstance), CliError> {
    let config = CliFullNodeConfig::load(full_node_args)
        .map_err(|e| CliError::ConfigFailed(format!("Error loading full node config: {}", e)))?;

    let db = create_storage(&config.db).await?;
    let da = create_full_node_da_layer(&config.da).await?;
    let telemetry = create_telemetry(
        &config.telemetry,
        vec![("node_type".to_string(), "fullnode".to_string())],
    )?;

    let full_node = create_prover_as_full_node(&config.full_node, db.clone(), da.clone())
        .map_err(|e| CliError::ConfigFailed(format!("Failed to create full node: {}", e)))?;

    Ok((Arc::new(full_node) as Arc<dyn NodeType>, telemetry))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Process interrupted, initiating graceful shutdown");
        },
        _ = terminate => {
            info!("Process terminated, initiating graceful shutdown")
        },
    }
}
