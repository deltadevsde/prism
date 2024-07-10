use clap::{Parser, Subcommand};
use config::{builder::DefaultState, ConfigBuilder, File, FileFormat};
use serde::Deserialize;
use std::sync::Arc;

use crate::da::{CelestiaConnection, LocalDataAvailabilityLayer};

use crate::da::DataAvailabilityLayer;

#[derive(Clone, Debug, Subcommand, Deserialize)]
pub enum Commands {
    LightClient,
    Sequencer,
}

#[derive(Parser, Clone, Debug, Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct CommandLineArgs {
    /// Log level
    #[arg(short, long)]
    log_level: Option<String>,

    /// Celestia Client websocket URL
    #[arg(short = 'c', long)]
    celestia_client: Option<String>,

    #[arg(short = 'r', long)]
    redis_client: Option<String>,

    /// Celestia Namespace ID
    #[arg(short = 'n', long)]
    celestia_namespace_id: Option<String>,

    /// Duration between epochs in seconds
    #[arg(short, long)]
    epoch_time: Option<u64>,

    /// IP address for the webserver to listen on
    #[arg(short, long)]
    host: Option<String>,

    /// Port number for the webserver to listen on
    #[arg(short, long)]
    port: Option<u16>,

    #[arg(long)]
    public_key: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

pub async fn initialize_da_layer(config: &Config) -> Arc<dyn DataAvailabilityLayer + 'static> {
    match &config.da_layer {
        DALayerOption::Celestia => {
            let celestia_conf = config.clone().celestia_config.unwrap();
            match CelestiaConnection::new(
                &celestia_conf.connection_string,
                None,
                &celestia_conf.namespace_id,
            )
            .await
            {
                Ok(da) => Arc::new(da) as Arc<dyn DataAvailabilityLayer + 'static>,
                Err(e) => {
                    panic!("connecting to celestia: {}", e);
                }
            }
        }
        DALayerOption::InMemory => {
            Arc::new(LocalDataAvailabilityLayer::new()) as Arc<dyn DataAvailabilityLayer + 'static>
        }
        DALayerOption::None => panic!("no da Layer"),
    }
}
