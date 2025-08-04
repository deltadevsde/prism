use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Deserialize;

use crate::cfg::ConfigSource;

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

#[derive(ValueEnum, Debug, Clone, Deserialize)]
pub enum LightClientPreset {
    Specter,
}

// #[derive(Args, Deserialize, Clone, Debug)]
// #[group(required = false, multiple = false)]
// pub struct CliPresetArgs {
//     #[arg(long)]
//     /// Start prism node in development mode
//     pub dev: bool,

//     #[arg(long)]
//     /// Start prism node with connection to specter testnet
//     pub specter: bool,
// }

// impl CliPresetArgs {
//     pub fn preset(&self) -> Option<LightClientPreset> {
//         if self.dev {
//             Some(LightClientPreset::Development)
//         } else if self.specter {
//             Some(LightClientPreset::Specter)
//         } else {
//             None
//         }
//     }
// }

#[derive(Args, Deserialize, Clone, Debug)]
pub struct LightClientCliArgs {
    #[arg(long)]
    /// Start light client with connection to specter testnet
    pub specter: bool,

    #[arg(short = 'c', long, default_value = "~/.prism/light_client.toml")]
    pub config_path: String,

    #[arg(short = 'k', long)]
    /// Prover's verifying key, used to verify epoch signatures. Expected to be a path to a file or
    /// base64-encoded SPKI DER content directly.
    pub verifying_key: Option<String>,

    #[command(flatten)]
    pub da: CliDaLayerArgs,
}

impl ConfigSource for LightClientCliArgs {
    type Preset = LightClientPreset;

    fn config_path(&self) -> &str {
        &self.config_path
    }

    fn preset(&self) -> Option<LightClientPreset> {
        self.specter.then_some(LightClientPreset::Specter)
    }
}

#[derive(ValueEnum, Debug, Clone, Deserialize)]
pub enum FullNodePreset {
    Specter,
    Development,
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

    #[command(flatten)]
    pub da: CliDaLayerArgs,

    #[command(flatten)]
    pub db: CliDatabaseArgs,

    #[command(flatten)]
    pub web: CliWebserverArgs,
}

impl ConfigSource for FullNodeCliArgs {
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

#[derive(ValueEnum, Debug, Clone, Deserialize)]
pub enum ProverPreset {
    Development,
    Specter,
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

    #[command(flatten)]
    pub da: CliDaLayerArgs,

    #[command(flatten)]
    pub db: CliDatabaseArgs,

    #[command(flatten)]
    pub web: CliWebserverArgs,
}

impl ConfigSource for ProverCliArgs {
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

#[derive(Args, Deserialize, Clone, Debug)]
#[group(required = false, multiple = true)]
pub struct CliWebserverArgs {
    #[arg(long)]
    pub webserver_active: Option<bool>,

    /// IP address for the webserver to listen on
    #[arg(long, requires = "webserver_active", default_value = "127.0.0.1")]
    pub host: Option<String>,

    /// Port number for the webserver to listen on
    #[arg(short, long, requires = "webserver_active", default_value = "41997")]
    pub port: Option<u16>,
}

#[derive(ValueEnum, Debug, Clone, Deserialize)]
pub enum CliDaLayerType {
    Celestia,
    InMemory,
}

#[derive(Args, Debug, Default, Clone, Deserialize)]
#[group(required = false, multiple = true)]
pub struct CliDaLayerArgs {
    #[arg(long)]
    pub da_type: Option<CliDaLayerType>,

    // Celestia specific arguments
    /// Celestia Snark Namespace ID
    #[arg(long)]
    pub celestia_snark_namespace_id: Option<String>,

    /// Celestia Transaction Namespace ID
    #[arg(long)]
    pub celestia_operation_namespace_id: Option<String>,

    /// Celestia Snark Namespace ID
    #[arg(long)]
    pub celestia_url: Option<String>,
}

#[derive(ValueEnum, Debug, Clone, Deserialize)]
pub enum CliDatabaseType {
    InMemory,
    RocksDB,
}

#[derive(Args, Deserialize, Clone, Debug)]
pub struct CliDatabaseArgs {
    #[arg(long, value_enum)]
    /// Storage backend to use. Default: `rocks-db`
    pub db_type: Option<CliDatabaseType>,

    /// Path to the RocksDB database, used when `db_type` is `rocks-db`
    #[arg(long)]
    pub rocksdb_path: Option<String>,
}
