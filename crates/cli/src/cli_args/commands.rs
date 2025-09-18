use clap::{Args, Parser, Subcommand};
use prism_presets::{FullNodePreset, LightClientPreset, ProverPreset};
use serde::Deserialize;

use super::{da::CliDaLayerArgs, database::CliDatabaseArgs, webserver::CliWebserverArgs};
use crate::apply_args::CliArgs;

#[derive(Parser, Clone, Debug, Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommands,
}

#[derive(Clone, Debug, Subcommand, Deserialize)]
pub enum CliCommands {
    LightClient(LightClientCliArgs),
    FullNode(FullNodeCliArgs),
    Prover(ProverCliArgs),
}

#[derive(Args, Deserialize, Clone, Debug)]
pub struct LightClientCliArgs {
    #[arg(long, conflicts_with = "specter")]
    /// Start light client in development mode
    pub dev: bool,

    #[arg(long, conflicts_with = "dev")]
    /// Start light client with connection to specter testnet
    pub specter: bool,

    #[arg(short = 'c', long, default_value = "~/.prism/light_client.toml")]
    /// Path to the light client configuration file
    pub config_path: String,

    #[arg(short = 'k', long)]
    /// Prover's verifying key, used to verify epoch signatures. Expected to be a path to a file or
    /// base64-encoded SPKI DER content directly.
    pub verifying_key: Option<String>,

    #[arg(long)]
    /// Whether to allow the verification of mock proofs
    /// Default: false
    pub allow_mock_proofs: Option<bool>,

    #[command(flatten)]
    pub da: CliDaLayerArgs,
}

impl CliArgs for LightClientCliArgs {
    type Preset = LightClientPreset;

    fn config_path(&self) -> &str {
        &self.config_path
    }

    fn preset(&self) -> Option<LightClientPreset> {
        if self.dev {
            Some(LightClientPreset::Development)
        } else if self.specter {
            Some(LightClientPreset::Specter)
        } else {
            None
        }
    }
}

#[derive(Args, Deserialize, Clone, Debug)]
pub struct FullNodeCliArgs {
    #[arg(long, conflicts_with = "specter")]
    /// Start full node in development mode
    pub dev: bool,

    #[arg(long, conflicts_with = "dev")]
    /// Start full node with connection to specter testnet
    pub specter: bool,

    #[arg(short = 'c', long, default_value = "~/.prism/full_node.toml")]
    pub config_path: String,

    #[arg(short = 'k', long)]
    /// Prover's verifying key, used to verify epoch signatures. Expected to be a path to a file or
    /// base64-encoded SPKI DER content directly.
    pub verifying_key: Option<String>,

    #[arg(long)]
    /// The height of the first prism block to consider
    /// Default: 1
    pub start_height: Option<u64>,

    #[command(flatten)]
    pub da: CliDaLayerArgs,

    #[command(flatten)]
    pub db: CliDatabaseArgs,

    #[command(flatten)]
    pub web: CliWebserverArgs,
}

impl CliArgs for FullNodeCliArgs {
    type Preset = FullNodePreset;

    fn config_path(&self) -> &str {
        &self.config_path
    }

    fn preset(&self) -> Option<FullNodePreset> {
        if self.dev {
            Some(FullNodePreset::Development)
        } else if self.specter {
            Some(FullNodePreset::Specter)
        } else {
            None
        }
    }
}

#[derive(Args, Deserialize, Clone, Debug)]
pub struct ProverCliArgs {
    #[arg(long, conflicts_with = "specter")]
    /// Start prover in development mode
    pub dev: bool,

    #[arg(long, conflicts_with = "dev")]
    /// Start prover with connection to specter testnet
    pub specter: bool,

    #[arg(short = 'c', long, default_value = "~/.prism/prover.toml")]
    pub config_path: String,

    #[arg(short = 'k', long)]
    /// Prover's signing key, used to sign finalized epochs. Expected to be a path to a PKCS#8
    /// PEM file.
    pub signing_key: Option<String>,

    #[arg(long)]
    /// Maximum number of epochs allowed without proofs before triggering action
    pub max_epochless_gap: Option<u64>,

    #[arg(long)]
    /// The height of the first prism block to consider
    /// Default: 1
    pub start_height: Option<u64>,

    #[arg(long)]
    /// Enable recursive proofs for more efficient verification
    pub recursive_proofs: Option<bool>,

    #[command(flatten)]
    pub da: CliDaLayerArgs,

    #[command(flatten)]
    pub db: CliDatabaseArgs,

    #[command(flatten)]
    pub web: CliWebserverArgs,
}

impl CliArgs for ProverCliArgs {
    type Preset = ProverPreset;

    fn config_path(&self) -> &str {
        &self.config_path
    }

    fn preset(&self) -> Option<ProverPreset> {
        if self.dev {
            Some(ProverPreset::Development)
        } else if self.specter {
            Some(ProverPreset::Specter)
        } else {
            None
        }
    }
}
