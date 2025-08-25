use prism_da::LightClientDAConfig;
use prism_lightclient::LightClientConfig;
use prism_presets::{ApplyPreset, LightClientPreset, PresetError};

#[derive(Clone, Debug, Default)]
pub struct UniffiLightClientConfig {
    pub da: LightClientDAConfig,
    pub light_client: LightClientConfig,
}

impl ApplyPreset<LightClientPreset> for UniffiLightClientConfig {
    fn apply_preset(&mut self, preset: &LightClientPreset) -> Result<(), PresetError> {
        self.da.apply_preset(preset)?;
        self.light_client.apply_preset(preset)?;
        Ok(())
    }
}
