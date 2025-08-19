use prism_da::{FullNodeDAConfig, LightClientDAConfig};
use prism_lightclient::LightClientConfig;
use prism_presets::{ApplyPreset, FullNodePreset, LightClientPreset, PresetError, ProverPreset};
use prism_prover::{FullNodeConfig, ProverConfig};
use prism_storage::DatabaseConfig;
use prism_telemetry::config::TelemetryConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CliLightClientConfig {
    pub da: LightClientDAConfig,
    pub telemetry: TelemetryConfig,

    #[serde(flatten)]
    pub light_client: LightClientConfig,
}

impl ApplyPreset<LightClientPreset> for CliLightClientConfig {
    fn apply_preset(&mut self, preset: &LightClientPreset) -> std::result::Result<(), PresetError> {
        self.da.apply_preset(preset)?;
        self.light_client.apply_preset(preset)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CliFullNodeConfig {
    pub db: DatabaseConfig,
    pub da: FullNodeDAConfig,
    pub telemetry: TelemetryConfig,

    #[serde(flatten)]
    pub full_node: FullNodeConfig,
}

impl ApplyPreset<FullNodePreset> for CliFullNodeConfig {
    fn apply_preset(&mut self, preset: &FullNodePreset) -> std::result::Result<(), PresetError> {
        self.db.apply_preset(preset)?;
        self.da.apply_preset(preset)?;
        self.full_node.apply_preset(preset)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CliProverConfig {
    pub db: DatabaseConfig,
    pub da: FullNodeDAConfig,
    pub telemetry: TelemetryConfig,

    #[serde(flatten)]
    pub prover: ProverConfig,
}

impl ApplyPreset<ProverPreset> for CliProverConfig {
    fn apply_preset(&mut self, preset: &ProverPreset) -> std::result::Result<(), PresetError> {
        self.db.apply_preset(preset)?;
        self.da.apply_preset(preset)?;
        self.prover.apply_preset(preset)?;
        Ok(())
    }
}
