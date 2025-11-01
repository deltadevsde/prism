use prism_lightclient::LightClientConfig;
use prism_presets::{ApplyPreset, FullNodePreset, LightClientPreset, PresetError, ProverPreset};
use prism_prover::{FullNodeConfig, ProverConfig};
use prism_telemetry::config::TelemetryConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CliLightClientConfig {
    #[serde(flatten)]
    pub light_client: LightClientConfig,

    pub telemetry: TelemetryConfig,
}

impl ApplyPreset<LightClientPreset> for CliLightClientConfig {
    fn apply_preset(&mut self, preset: &LightClientPreset) -> std::result::Result<(), PresetError> {
        self.light_client.apply_preset(preset)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CliFullNodeConfig {
    pub telemetry: TelemetryConfig,

    #[serde(flatten)]
    pub full_node: FullNodeConfig,
}

impl ApplyPreset<FullNodePreset> for CliFullNodeConfig {
    fn apply_preset(&mut self, preset: &FullNodePreset) -> std::result::Result<(), PresetError> {
        self.full_node.apply_preset(preset)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CliProverConfig {
    pub telemetry: TelemetryConfig,

    #[serde(flatten)]
    pub prover: ProverConfig,
}

impl ApplyPreset<ProverPreset> for CliProverConfig {
    fn apply_preset(&mut self, preset: &ProverPreset) -> std::result::Result<(), PresetError> {
        self.prover.apply_preset(preset)?;
        Ok(())
    }
}
