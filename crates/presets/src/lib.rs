use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const PRESET_SPECTER_PUBLIC_KEY_BASE64: &str =
    "MCowBQYDK2VwAyEAL2ilppK59Kq3aAMB/wpxdVGaI53DHPMdY6fcRodyFaA=";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightClientPreset {
    Specter,
}

impl FromStr for LightClientPreset {
    type Err = PresetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "specter" => Ok(LightClientPreset::Specter),
            _ => Err(PresetError::UnknownPreset(format!(
                "Unknown LightClientPreset: {}",
                s
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FullNodePreset {
    Development,
    Specter,
}

impl FromStr for FullNodePreset {
    type Err = PresetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Ok(FullNodePreset::Development),
            "specter" => Ok(FullNodePreset::Specter),
            _ => Err(PresetError::UnknownPreset(format!(
                "Unknown FullNodePreset: {}",
                s
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProverPreset {
    Development,
    Specter,
}

impl FromStr for ProverPreset {
    type Err = PresetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "development" => Ok(ProverPreset::Development),
            "specter" => Ok(ProverPreset::Specter),
            _ => Err(PresetError::UnknownPreset(format!(
                "Unknown ProverPreset: {}",
                s
            ))),
        }
    }
}

pub trait Preset: Clone + Serialize + for<'a> Deserialize<'a> {}

impl Preset for LightClientPreset {}
impl Preset for FullNodePreset {}
impl Preset for ProverPreset {}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum PresetError {
    #[error("Preset failed: {0}")]
    ApplicationFailed(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Unknown preset: {0}")]
    UnknownPreset(String),
}

pub trait ApplyPreset<P: Preset>: Default {
    fn default_with_preset(preset: &P) -> Result<Self, PresetError> {
        let mut instance = Self::default();
        instance.apply_preset(preset)?;
        Ok(instance)
    }

    fn apply_preset(&mut self, preset: &P) -> Result<(), PresetError>;
}
