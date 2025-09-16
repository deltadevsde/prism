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
    /// - A filesystem path to a SPKI PEM file (e.g., `~/.prism/prover_key.spki`)
    /// - A base64-encoded verifying key string
    ///
    /// Must correspond to the signing key used by a trusted prover.
    #[serde(rename = "verifying_key")]
    pub verifying_key_str: String,

    /// Enabling this option bypasses proof verification and should only be used
    /// in development or testing environments. In production, this must be set
    /// to `false` to ensure the integrity and security of the light client.
    pub allow_mock_proofs: bool,
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

        Self {
            verifying_key_str: verifying_key_path.to_string_lossy().into_owned(),
            allow_mock_proofs: false,
        }
    }
}

impl ApplyPreset<LightClientPreset> for LightClientConfig {
    fn apply_preset(&mut self, preset: &LightClientPreset) -> Result<(), PresetError> {
        match preset {
            LightClientPreset::Development => {
                self.allow_mock_proofs = true;
                Ok(())
            }
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
    let mut light_client = LightClient::new(da, verifying_key, cancellation_token);

    if config.allow_mock_proofs {
        light_client.enable_mock_proof_verification();
    }
    Ok(light_client)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use prism_da::memory::InMemoryDataAvailabilityLayer;
    use prism_presets::{LightClientPreset, PRESET_SPECTER_PUBLIC_KEY_BASE64};
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn test_light_client_config_default() {
        let config = LightClientConfig::default();

        #[cfg(not(target_arch = "wasm32"))]
        {
            // On non-wasm, should default to home directory path
            assert!(config.verifying_key_str.contains(".prism/prover_key.spki"));
        }

        #[cfg(target_arch = "wasm32")]
        {
            // On wasm, should default to relative path
            assert_eq!(config.verifying_key_str, ".prism/prover_key.spki");
        }
    }

    #[test]
    fn test_light_client_config_apply_specter_preset() {
        let mut config = LightClientConfig::default();
        let result = config.apply_preset(&LightClientPreset::Specter);

        assert!(result.is_ok());
        assert_eq!(config.verifying_key_str, PRESET_SPECTER_PUBLIC_KEY_BASE64);
    }

    #[test]
    fn test_create_light_client_with_base64_key() {
        let da = Arc::new(InMemoryDataAvailabilityLayer::default());
        let config = LightClientConfig {
            verifying_key_str: PRESET_SPECTER_PUBLIC_KEY_BASE64.to_string(),
            ..Default::default()
        };
        let cancellation_token = CancellationToken::new();

        let result = create_light_client(da, &config, cancellation_token);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_light_client_with_invalid_key() {
        let da = Arc::new(InMemoryDataAvailabilityLayer::default());
        let config = LightClientConfig {
            verifying_key_str: "invalid_key".to_string(),
            ..Default::default()
        };
        let cancellation_token = CancellationToken::new();

        let result = create_light_client(da, &config, cancellation_token);
        assert!(result.is_err());
    }
}
