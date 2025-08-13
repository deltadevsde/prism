use prism_da::LightDataAvailabilityLayer;
use prism_keys::VerifyingKey;
use prism_presets::{
    ApplyPreset, LightClientPreset, PRESET_SPECTER_PUBLIC_KEY_BASE64, PresetError,
};
use serde::{Deserialize, Serialize};
use std::{env::current_dir, result::Result, sync::Arc};
use tokio_util::sync::CancellationToken;

use crate::LightClient;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LightClientConfig {
    #[serde(rename = "verifying_key")]
    pub verifying_key_str: String,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        LightClientConfig {
            verifying_key_str: dirs::home_dir()
                .unwrap_or_else(|| current_dir().unwrap_or_default())
                .join(".prism/prover_key.spki")
                .to_string_lossy()
                .into_owned(),
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

pub fn create_light_client(
    #[cfg(not(target_arch = "wasm32"))] da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
    #[cfg(target_arch = "wasm32")] da: Arc<dyn LightDataAvailabilityLayer>,
    config: &LightClientConfig,
    cancellation_token: CancellationToken,
) -> anyhow::Result<LightClient> {
    let verifying_key = VerifyingKey::from_spki_pem_path_or_base64(&config.verifying_key_str)?;
    Ok(LightClient::new(da, verifying_key, cancellation_token))
}
