use clap::{Args, ValueEnum};
use prism_da::celestia::CelestiaNetwork;
use serde::Deserialize;

#[derive(ValueEnum, Debug, Clone, Deserialize)]
pub enum CliDaLayerType {
    Celestia,
    InMemory,
}

#[derive(ValueEnum, Debug, Clone, Deserialize)]
pub enum CliCelestiaLightClientStoreType {
    InMemory,
    Disk,
}

#[derive(ValueEnum, Debug, Clone, Deserialize)]
pub enum CliCelestiaNetwork {
    Arabica,
    Mocha,
    Mainnet,
}

impl From<CliCelestiaNetwork> for CelestiaNetwork {
    fn from(network: CliCelestiaNetwork) -> Self {
        match network {
            CliCelestiaNetwork::Arabica => Self::Arabica,
            CliCelestiaNetwork::Mocha => Self::Mocha,
            CliCelestiaNetwork::Mainnet => Self::Mainnet,
        }
    }
}

#[derive(Args, Debug, Clone, Default, Deserialize)]
#[group(required = false, multiple = true)]
pub struct CliDaLayerArgs {
    #[arg(long)]
    pub da_type: Option<CliDaLayerType>,

    // Celestia specific arguments
    /// Celestia Snark Namespace ID
    #[arg(long)]
    pub celestia_snark_namespace_id: Option<String>,

    /// Celestia Transaction Namespace ID
    #[arg(long)]
    pub celestia_operation_namespace_id: Option<String>,

    /// WebSocket URL for connecting to Celestia node
    #[arg(long)]
    pub celestia_url: Option<String>,

    #[arg(long)]
    /// Type of the store that is being used to store block data.
    /// [default: disk]
    pub celestia_store_type: Option<CliCelestiaLightClientStoreType>,

    #[arg(long, required_if_eq("celestia_store_type", "disk"))]
    /// Path to the directory, in which the light client stores block data.
    /// [default: `~/.prism/data/light_client`]
    pub celestia_disk_store_path: Option<String>,

    #[arg(long)]
    /// Celestia network to connect to
    pub celestia_network: Option<CliCelestiaNetwork>,

    #[arg(long)]
    /// Fetch timeout in seconds for Celestia operations
    pub celestia_fetch_timeout: Option<u64>,

    #[arg(long)]
    /// Maximum number of retries for failed Celestia operations
    pub celestia_fetch_max_retries: Option<u64>,

    #[arg(long)]
    /// Pruning window in seconds for light client data
    pub celestia_pruning_window: Option<u64>,
}
