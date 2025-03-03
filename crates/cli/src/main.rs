mod node_types;
mod settings;

use crate::settings::{
    Cli, Commands, settings as load_settings, initialize_db, initialize_da_layer, initialize_light_da_layer
};
use crate::node_types::NodeType;
use clap::Parser;
use log::{error, info, warn};
use sp1_sdk::{HashableKey, Prover as _, ProverClient};
use std::io::{Error, ErrorKind};
use prism_lightclient::LightClient;
use prism_prover::Prover;
use prism_lightclient::events::EventChannel;
use std::sync::Arc;
use prism_keys::SigningKey;

extern crate log;

pub const PRISM_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

pub const SIGNING_KEY_ID: &str = "prism";

/// The main function that initializes and runs a prism client.
#[tokio::main()]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let args = match cli.clone().command {
        Commands::LightClient(args) | Commands::Prover(args) | Commands::FullNode(args) => args,
    };

    let config =
        load_settings(args.clone()).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    let start_height = config.clone().network.celestia_config.start_height;

    let node: Arc<dyn NodeType> = match cli.command {
        Commands::LightClient(_) => {
            let verifying_key = config.network.verifying_key.clone();

            let da = initialize_light_da_layer(&config).await.map_err(|e| {
                error!("error initializing light da layer: {}", e);
                Error::new(ErrorKind::Other, e.to_string())
            })?;

            let client = ProverClient::builder().mock().build();
            let (_, vk) = client.setup(PRISM_ELF);
            let event_channel = EventChannel::new();

            Arc::new(LightClient::new(
                da,
                start_height,
                verifying_key,
                vk.bytes32(),
                event_channel.publisher(),
            ))
        }
        Commands::Prover(_args) => {
            let db =
                initialize_db(&config).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let da = initialize_da_layer(&config)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            info!(
                "keystore type: {:?}",
                config.clone().keystore.keystore_type
            );

            let signing_key = get_signing_key(
                Some(config.keystore.keystore_type.clone()),
                Some(config.keystore.file.file_path.clone())
            )?;

            let verifying_key = config
                .network
                .verifying_key
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "prover verifying key not found"))?;

            let webserver_config = &config.webserver;
            let prover_cfg = prism_prover::Config {
                prover: true,
                batcher: false,
                webserver: prism_prover::webserver::WebServerConfig {
                    enabled: webserver_config.enabled,
                    host: webserver_config.host.clone(),
                    port: webserver_config.port,
                },
                signing_key: signing_key.unwrap_or_else(|| {
                    warn!("No signing key provided, using a dummy key");
                    SigningKey::new_ed25519()
                }),
                verifying_key,
                start_height,
            };

            Arc::new(Prover::new(db, da, &prover_cfg).map_err(|e| {
                error!("error initializing prover: {}", e);
                Error::new(ErrorKind::Other, e.to_string())
            })?)
        }
        Commands::FullNode(_) => {
            let db =
                initialize_db(&config).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let da = initialize_da_layer(&config)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            info!(
                "keystore type: {:?}",
                config.clone().keystore.keystore_type
            );

            let signing_key = get_signing_key(
                Some(config.keystore.keystore_type.clone()),
                Some(config.keystore.file.file_path.clone())
            )?;

            let verifying_key = config
                .network
                .verifying_key
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "prover verifying key not found"))?;

            let webserver_config = &config.webserver;
            let prover_cfg = prism_prover::Config {
                prover: false,
                batcher: true,
                webserver: prism_prover::webserver::WebServerConfig {
                    enabled: webserver_config.enabled,
                    host: webserver_config.host.clone(),
                    port: webserver_config.port,
                },
                signing_key: signing_key.unwrap_or_else(|| {
                    warn!("No signing key provided, using a dummy key");
                    SigningKey::new_ed25519()
                }),
                verifying_key,
                start_height,
            };

            Arc::new(Prover::new(db, da, &prover_cfg).map_err(|e| {
                error!("error initializing prover: {}", e);
                Error::new(ErrorKind::Other, e.to_string())
            })?)
        }
    };

    node.start().await.map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
}

fn get_signing_key(
    keystore_type: Option<String>,
    keystore_path: Option<String>,
) -> Result<Option<prism_keys::SigningKey>, Error> {
    match (keystore_type.as_deref(), keystore_path) {
        (Some("keychain"), _) => {
            info!("Using Keychain");
            Ok(None)
        }
        (Some("file"), Some(file_path)) => {
            let resolved_path = if std::path::Path::new(&file_path).is_absolute() {
                file_path
            } else {
                let home_path = std::env::var("PRISM_HOME_PATH").unwrap_or_else(|_| {
                    dirs::home_dir()
                        .map(|p| format!("{}/.prism/", p.to_string_lossy()))
                        .unwrap_or_else(|| "./".to_string())
                });
                format!("{}/{}", home_path, file_path)
            };

            info!("Using file keystore at {}", resolved_path);
            Ok(None)
        }
        _ => Ok(None),
    }
}
