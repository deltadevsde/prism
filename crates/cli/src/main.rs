mod apply_args;
mod cli_args;
mod config;
mod file_utils;
mod node_types;

use clap::Parser;
use dotenvy::dotenv;
use node_types::NodeType;
use prism_cli::error::CliError;
use prism_events::EventSubscriber;
use prism_lightclient::create_light_client;
use prism_prover::{create_prover_as_full_node, create_prover_as_prover};
use prism_telemetry_registry::{TelemetryInstance, create_telemetry};
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

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
    let event_sub = events.subscribe();
    shutdown_signal(event_sub).await;

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

    let light_client = create_light_client(&config.light_client)
        .await
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

    let prover = create_prover_as_prover(&config.prover)
        .await
        .map_err(|e| CliError::ConfigFailed(format!("Failed to create prover: {}", e)))?;

    Ok((Arc::new(prover) as Arc<dyn NodeType>, telemetry))
}

async fn create_full_node(
    full_node_args: &FullNodeCliArgs,
) -> Result<(Arc<dyn NodeType>, TelemetryInstance), CliError> {
    let config = CliFullNodeConfig::load(full_node_args)
        .map_err(|e| CliError::ConfigFailed(format!("Error loading full node config: {}", e)))?;

    let telemetry = create_telemetry(
        &config.telemetry,
        vec![("node_type".to_string(), "fullnode".to_string())],
    )?;

    let full_node = create_prover_as_full_node(&config.full_node)
        .await
        .map_err(|e| CliError::ConfigFailed(format!("Failed to create full node: {}", e)))?;

    Ok((Arc::new(full_node) as Arc<dyn NodeType>, telemetry))
}

async fn shutdown_signal(mut sub: EventSubscriber) {
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Process interrupted, initiating graceful shutdown");
                break;
            },
            _ = terminate_signal() => {
                info!("Process terminated, initiating graceful shutdown");
                break;
            },
            Ok(event_info) = sub.recv() => {
                if event_info.is_error() {
                    error!("Error event received: {}", event_info.event);
                    break;
                }
                info!("{}", event_info.event);
            }
        }
    }
}

#[cfg(unix)]
async fn terminate_signal() -> std::io::Result<()> {
    signal::unix::signal(signal::unix::SignalKind::terminate())?.recv().await;
    Ok(())
}

#[cfg(not(unix))]
async fn terminate_signal() -> std::io::Result<()> {
    std::future::pending().await
}
