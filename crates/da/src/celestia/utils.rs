use std::{fmt, str::FromStr, time::Duration};

use anyhow::{Context, Result};
use celestia_types::nmt::Namespace;
use lumina_node::{
    network::Network as CelestiaNetwork,
    node::{DEFAULT_PRUNING_DELAY, DEFAULT_SAMPLING_WINDOW},
};
use prism_keys::{SigningKey, VerifyingKey};
use prism_serde::{self, base64::FromBase64, hex::FromHex};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CelestiaConfig {
    pub connection_string: String,
    pub start_height: u64,
    pub snark_namespace_id: String,
    pub operation_namespace_id: String,
    pub sampling_window: Duration,
    pub pruning_delay: Duration,
    pub fetch_timeout: Duration,
    pub fetch_max_retries: u64,
}

impl Default for CelestiaConfig {
    fn default() -> Self {
        CelestiaConfig {
            connection_string: "ws://localhost:26658".to_string(),
            start_height: 4851608,
            sampling_window: DEFAULT_SAMPLING_WINDOW,
            pruning_delay: DEFAULT_PRUNING_DELAY,
            snark_namespace_id: "00000000000000de1008".to_string(),
            operation_namespace_id: "00000000000000de1009".to_string(),
            fetch_timeout: Duration::from_secs(120),
            fetch_max_retries: 5,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Network {
    Specter,
    Custom(String),
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Specter => write!(f, "specter"),
            Network::Custom(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    pub network: Network,
    pub celestia_network: CelestiaNetwork,
    /// The verifying key of the prover
    pub verifying_key: VerifyingKey,
    pub celestia_config: Option<CelestiaConfig>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            network: Network::Custom("custom".to_string()),
            celestia_network: CelestiaNetwork::custom("private").unwrap(),
            // TODO: This is just a placeholder, don't let this get merged
            verifying_key: SigningKey::new_ed25519().verifying_key(),
            celestia_config: None,
        }
    }
}

impl FromStr for Network {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "specter" | "Specter" | "devnet" => Ok(Network::Specter),
            _ => Ok(Network::Custom(s.to_string())),
        }
    }
}

impl Network {
    pub fn config(&self) -> NetworkConfig {
        match self {
            Network::Specter => NetworkConfig {
                network: Network::Specter,
                celestia_network: CelestiaNetwork::Mocha,
                verifying_key: VerifyingKey::from_base64(
                    "L2ilppK59Kq3aAMB/wpxdVGaI53DHPMdY6fcRodyFaA=",
                )
                .unwrap(),
                celestia_config: Some(CelestiaConfig {
                    start_height: 5725333,
                    snark_namespace_id: "000000000000000000000000000000000000707269736d5350457331"
                        .to_string(),
                    operation_namespace_id:
                        "000000000000000000000000000000000000707269736d5350456f31".to_string(),
                    ..CelestiaConfig::default()
                }),
            },
            Network::Custom(id) => NetworkConfig {
                network: Network::Custom(id.clone()),
                ..Default::default()
            },
        }
    }
}

pub fn create_namespace(namespace_hex: &str) -> Result<Namespace> {
    let decoded_hex = Vec::<u8>::from_hex(namespace_hex).context(format!(
        "Failed to decode namespace hex '{}'",
        namespace_hex
    ))?;

    Namespace::new_v0(&decoded_hex).context(format!(
        "Failed to create namespace from '{}'",
        namespace_hex
    ))
}
