pub mod full_node;
pub mod light_client;
pub mod utils;

use std::time::Duration;

pub use lumina_node::{
    network::Network as CelestiaNetwork,
    node::{DEFAULT_PRUNING_WINDOW, SAMPLING_WINDOW},
};

pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_FETCH_MAX_RETRIES: u64 = 5;

// Preset specific constants
pub const DEVNET_SPECTER_SNARK_NAMESPACE_ID: &str =
    "000000000000000000000000000000000000707269736d5350457331";
pub const DEVNET_SPECTER_OP_NAMESPACE_ID: &str =
    "000000000000000000000000000000000000707269736d5350456f31";
