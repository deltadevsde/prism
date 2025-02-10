use std::str::FromStr;

use lumina_node::network::Network as CelestiaNetwork;
use prism_da::celestia::CelestiaConfig;
use prism_keys::VerifyingKey;
use prism_serde::{self, base64::FromBase64};
use serde::{Deserialize, Serialize};

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
            celestia_network: CelestiaNetwork::Private,
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
                    start_height: 4180975,
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
