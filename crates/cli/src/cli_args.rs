use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Parser, Clone, Debug, Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommands,
}

#[derive(Clone, Debug, Subcommand, Deserialize)]
pub enum CliCommands {
    LightClient(CliCommandArgs),
    FullNode(CliCommandArgs),
    Prover(CliCommandArgs),
}

#[derive(Args, Deserialize, Clone, Debug)]
pub struct CliCommandArgs {
    #[arg(short = 'n', long, default_value = "local")]
    pub network_name: Option<String>,

    #[arg(long)]
    /// Prover's verifying key, used to verify epoch signatures. Expected to be a base64-encoded string.
    pub verifying_key: Option<String>,

    #[arg(long)]
    pub home_path: Option<String>,

    #[command(flatten)]
    pub database: CliDatabaseArgs,

    /// The type of keystore to use.
    ///
    /// Can be one of: `keychain`, `file`.
    #[arg(long, default_value = "keychain")]
    pub keystore_type: Option<String>,

    /// The path to the keystore.
    ///
    /// This is only used if the keystore type is `file`.
    #[arg(long, default_value = "~/.prism/keystore.json")]
    pub keystore_path: Option<String>,

    #[command(flatten)]
    pub celestia: CliCelestiaArgs,

    #[command(flatten)]
    pub webserver: CliWebserverArgs,
}

#[derive(Args, Deserialize, Clone, Debug)]
#[group(required = false, multiple = true)]
pub struct CliCelestiaArgs {
    /// Celestia Client websocket URL
    #[arg(short = 'c', long)]
    pub celestia_client: Option<String>,

    /// Celestia Snark Namespace ID
    #[arg(long)]
    pub snark_namespace_id: Option<String>,

    /// Celestia Transaction Namespace ID
    #[arg(long)]
    pub operation_namespace_id: Option<String>,

    /// Height to start searching the DA layer for SNARKs on
    #[arg(short = 's', long)]
    pub celestia_start_height: Option<u64>,
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
    #[arg(short, long, requires = "webserver_active")]
    pub port: Option<u16>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum CliDaLayerType {
    Celestia,
    #[default]
    InMemory,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
pub enum CliDatabaseType {
    #[default]
    InMemory,
    Redis,
    RocksDB,
}

#[derive(Args, Deserialize, Clone, Debug)]
pub struct CliDatabaseArgs {
    #[arg(long, value_enum, default_value_t = CliDatabaseType::RocksDB)]
    /// Storage backend to use. Default: `rocks-db`
    pub db_type: CliDatabaseType,

    /// Path to the RocksDB database, used when `db_type` is `rocks-db`
    #[arg(long)]
    pub rocksdb_path: Option<String>,

    /// Connection string to Redis, used when `db_type` is `redis`
    #[arg(long, required_if_eq("db_type", "redis"))]
    pub redis_url: Option<String>,
}
