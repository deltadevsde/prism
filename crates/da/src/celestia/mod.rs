pub mod full_node;
pub mod light_client;
pub mod utils;

use std::time::Duration;

pub use lumina_node::{
    network::Network as CelestiaNetwork,
    node::{DEFAULT_PRUNING_DELAY, DEFAULT_SAMPLING_WINDOW},
};
pub use utils::CelestiaConfig;

pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_FETCH_MAX_RETRIES: u64 = 5;
