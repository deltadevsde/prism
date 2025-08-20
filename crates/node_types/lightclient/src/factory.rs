use prism_da::LightDataAvailabilityLayer;
use prism_keys::VerifyingKey;
use prism_presets::{
    ApplyPreset, LightClientPreset, PRESET_SPECTER_PUBLIC_KEY_BASE64, PresetError,
};
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use std::env;
use std::{path::PathBuf, result::Result, sync::Arc};
use tokio_util::sync::CancellationToken;

use crate::LightClient;

/// Configuration for Prism light clients.
///
/// Contains parameters for verifying SNARK proofs from the prover network.
/// The verifying key must match the signing key used by a trusted prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LightClientConfig {
    /// Path to the verifying key file or base64-encoded verifying key.
    ///
    /// Can be either:
    /// - A filesystem path to a SPKI PEM file (e.g., "~/.prism/prover_key.spki")
    /// - A base64-encoded verifying key string
    ///
    /// Must correspond to the signing key used by a trusted prover.
    #[serde(rename = "verifying_key")]
    pub verifying_key_str: String,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let verifying_key_path = dirs::home_dir()
            .or_else(|| env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".prism/prover_key.spki");

        #[cfg(target_arch = "wasm32")]
        let verifying_key_path = PathBuf::from(".prism/prover_key.spki");

        LightClientConfig {
            verifying_key_str: verifying_key_path.to_string_lossy().into_owned(),
        }
    }
}

impl ApplyPreset<LightClientPreset> for LightClientConfig {
    fn apply_preset(&mut self, preset: &LightClientPreset) -> Result<(), PresetError> {
        match &preset {
            LightClientPreset::Specter => {
                self.verifying_key_str = PRESET_SPECTER_PUBLIC_KEY_BASE64.to_string();
                Ok(())
            }
        }
    }
}

/// Creates a new light client instance with the given configuration.
///
/// The light client verifies SNARK proofs and maintains minimal state for
/// efficient interaction with the Prism network.
///
/// See the crate-level documentation for usage examples and integration patterns.
pub fn create_light_client(
    #[cfg(not(target_arch = "wasm32"))] da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
    #[cfg(target_arch = "wasm32")] da: Arc<dyn LightDataAvailabilityLayer>,
    config: &LightClientConfig,
    cancellation_token: CancellationToken,
) -> anyhow::Result<LightClient> {
    let verifying_key = VerifyingKey::from_spki_pem_path_or_base64(&config.verifying_key_str)?;
    Ok(LightClient::new(da, verifying_key, cancellation_token))
}
