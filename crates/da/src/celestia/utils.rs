use std::{future::Future, str::FromStr};

use anyhow::{anyhow, Context, Result};
use celestia_types::{nmt::Namespace, Blob};
use lumina_node::network::Network as CelestiaNetwork;
use prism_keys::VerifyingKey;
use prism_serde::{self, base64::FromBase64, binary::FromBinary, hex::FromHex};
use serde::{Deserialize, Serialize};

use crate::FinalizedEpoch;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CelestiaConfig {
    pub connection_string: String,
    pub start_height: u64,
    pub snark_namespace_id: String,
    pub operation_namespace_id: String,
}

impl Default for CelestiaConfig {
    fn default() -> Self {
        CelestiaConfig {
            connection_string: "ws://localhost:26658".to_string(),
            start_height: 4616930,
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
            network: Network::Specter,
            celestia_network: CelestiaNetwork::Mocha,
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

impl TryFrom<&Blob> for FinalizedEpoch {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        FinalizedEpoch::decode_from_bytes(&value.data).map_err(|_| {
            anyhow!(format!(
                "Failed to decode blob into FinalizedEpoch: {value:?}"
            ))
        })
    }
}

pub fn spawn_task<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    #[cfg(target_arch = "wasm32")]
    {
        wasm_bindgen_futures::spawn_local(future);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::spawn(future);
    }
}
