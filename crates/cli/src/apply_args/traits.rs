use anyhow::{Context, Result, bail};
use config::{Config, Environment, File};
use dirs::home_dir;
use prism_presets::{ApplyPreset, Preset};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, fs, path::Path};

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

    if let Err(e) = ensure_config_directory_exists(&expanded_path) {
        println!("Could not ensure config directory exists {}", e);
        return Ok(T::default());
    }

    let config_source = match Config::builder()
        .add_source(File::with_name(&expanded_path))
        .add_source(Environment::with_prefix("PRISM").separator("__"))
        .build()
    {
        Ok(config_source) => config_source,
        Err(e) => {
            println!("Failed to build config: {}. Using defaults.", e);
            return Ok(T::default());
        }
    };

    let config = match config_source.try_deserialize() {
        Ok(config) => config,
        Err(e) => {
            println!("Failed to deserialize config: {}. Using defaults.", e);
            return Ok(T::default());
        }
    };

    Ok(config)
}

fn ensure_config_directory_exists(config_path: impl AsRef<Path>) -> Result<()> {
    // If the path already exists, we're good
    if config_path.as_ref().exists() {
        return Ok(());
    }

    // Create parent directories if they don't exist
    if let Some(parent) = config_path.as_ref().parent() {
        return fs::create_dir_all(parent).context("Failed to create config directory");
    }

    bail!("Unable to create config directory");
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = home_dir() {
            return path.replacen("~", &home.to_string_lossy(), 1);
        }
    }
    path.to_string()
}
