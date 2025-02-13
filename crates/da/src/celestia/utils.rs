use std::{str::FromStr, time::Duration};

use anyhow::{Context, Result};
use celestia_types::nmt::Namespace;
use lumina_node::{
    network::Network as CelestiaNetwork,
    node::{DEFAULT_PRUNING_DELAY, DEFAULT_SAMPLING_WINDOW},
};
use prism_keys::VerifyingKey;
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
}

impl Default for CelestiaConfig {
    fn default() -> Self {
        CelestiaConfig {
            connection_string: "ws://localhost:26658".to_string(),
            start_height: 4616930,
            sampling_window: DEFAULT_SAMPLING_WINDOW,
            pruning_delay: DEFAULT_PRUNING_DELAY,
            snark_namespace_id: "00000000000000de1008".to_string(),
            operation_namespace_id: "00000000000000de1009".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Network {
    Specter,
    Custom(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    pub network: Network,
    pub celestia_network: CelestiaNetwork,
    /// The verifying key of the prover
    pub verifying_key: Option<VerifyingKey>,
    pub celestia_config: Option<CelestiaConfig>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            network: Network::Custom("custom".to_string()),
            celestia_network: CelestiaNetwork::custom("private").unwrap(),
            verifying_key: None,
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
                verifying_key: Some(
                    VerifyingKey::from_base64("L2ilppK59Kq3aAMB/wpxdVGaI53DHPMdY6fcRodyFaA=")
                        .unwrap(),
                ),
                celestia_config: Some(CelestiaConfig {
                    start_height: 4667138,
                    snark_namespace_id: "000000000000000000000000000000000000707269736d5350457330"
                        .to_string(),
                    operation_namespace_id:
                        "000000000000000000000000000000000000707269736d5350456f30".to_string(),
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
