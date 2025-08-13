use prism_da::LightClientDAConfig;
use prism_lightclient::LightClientConfig;
use prism_presets::{ApplyPreset, LightClientPreset, PresetError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WasmLightClientConfigError {
    #[error("Invalid preset: {0}")]
    InvalidPreset(String),
}

#[derive(Debug, Clone, Default)]
pub struct WasmLightClientConfig {
    pub da: LightClientDAConfig,
    pub light_client: LightClientConfig,
}

impl ApplyPreset<LightClientPreset> for WasmLightClientConfig {
    fn apply_preset(&mut self, preset: &LightClientPreset) -> Result<(), PresetError> {
        self.da.apply_preset(preset)?;
        self.light_client.apply_preset(preset)?;
        Ok(())
    }
}
