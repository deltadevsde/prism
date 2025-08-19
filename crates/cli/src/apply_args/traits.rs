use anyhow::Result;
use config::{Config, Environment, File};
use prism_presets::{ApplyPreset, Preset};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::warn;

use crate::file_utils::{ensure_file_directory_exists, expand_tilde};

/// Trait for CLI argument types that provide configuration sources
pub trait CliArgs {
    type Preset: prism_presets::Preset;
    fn config_path(&self) -> &str;
    fn preset(&self) -> Option<Self::Preset>;
}

/// Trait for configuration types that can be loaded from files and CLI arguments
#[allow(dead_code)] // clippy not able ti
pub trait CliOverridableConfig<P: Preset>:
    Sized + Serialize + for<'de> Deserialize<'de> + Debug + Default + ApplyPreset<P>
{
    type CliArgs: CliArgs<Preset = P>;

    /// Load configuration from file and CLI arguments
    fn load(cli_args: &Self::CliArgs) -> Result<Self> {
        let mut config: Self = load_config(cli_args.config_path())?;

        // Apply preset if specified in CLI args
        if let Some(preset) = cli_args.preset() {
            config.apply_preset(&preset)?;
        }

        config.apply_cli_args(cli_args)?;

        println!("Final config:\n{}", toml::to_string_pretty(&config)?);

        Ok(config)
    }

    /// Apply CLI arguments to override config values
    fn apply_cli_args(&mut self, args: &Self::CliArgs) -> Result<()>;
}

fn load_config<P: Preset, T: CliOverridableConfig<P>>(config_path: &str) -> Result<T> {
    let expanded_path = expand_tilde(config_path);

    if let Err(e) = ensure_file_directory_exists(&expanded_path) {
        warn!("Could not ensure config {expanded_path} exists: {e}");
    }

    let config = match Config::builder()
        .add_source(File::with_name(&expanded_path).required(false))
        .add_source(Environment::with_prefix("PRISM").separator("__").try_parsing(true))
        .build()
        .and_then(|config_source| config_source.try_deserialize())
    {
        Ok(config) => config,
        Err(e) => {
            println!("Failed to load config: {}. Using defaults.", e);
            return Ok(T::default());
        }
    };

    Ok(config)
}
