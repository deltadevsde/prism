use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

/// Command-line interface for the Prism application
#[derive(Parser, Clone, Debug, Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Available commands
#[derive(Clone, Debug, Subcommand, Deserialize)]
pub enum Commands {
    /// Start a light client node
    LightClient(CommandArgs),

    /// Start a full node
    FullNode(CommandArgs),

    /// Start a prover node
    Prover(CommandArgs),
}

/// Common command-line arguments for all node types
#[derive(Args, Deserialize, Clone, Debug)]
pub struct CommandArgs {
    /// Log level (ERROR, WARN, INFO, DEBUG, TRACE)
    #[arg(short, long, default_value = "INFO", env = "PRISM_LOG_LEVEL")]
    pub log_level: String,

    /// Network name (local, testnet, mainnet)
    #[arg(short = 'n', long, default_value = "local", env = "PRISM_NETWORK_NAME")]
    pub network_name: String,

    /// Prover's verifying key, used to verify epoch signatures
    /// Expected to be a base64-encoded string.
    #[arg(long, env = "PRISM_VERIFYING_KEY")]
    pub verifying_key: Option<String>,

    /// Path to the prism home directory
    #[arg(long, env = "PRISM_HOME_PATH")]
    pub home_path: Option<String>,

    /// Database configuration arguments
    #[command(flatten)]
    pub database: DatabaseArgs,

    /// The type of keystore to use (keychain, file)
    #[arg(long, default_value = "keychain", env = "PRISM_KEYSTORE_TYPE")]
    pub keystore_type: Option<String>,

    /// The path to the keystore file
    /// Only used if the keystore type is "file"
    #[arg(long, default_value = "keystore.json", env = "PRISM_KEYSTORE_FILE_PATH")]
    pub keystore_path: Option<String>,

    /// Celestia-specific configuration arguments
    #[command(flatten)]
    pub celestia: CelestiaArgs,

    /// Web server configuration arguments
    #[command(flatten)]
    pub webserver: WebserverArgs,
}

/// Celestia-specific configuration arguments
#[derive(Args, Deserialize, Clone, Debug)]
#[group(required = false, multiple = true)]
pub struct CelestiaArgs {
    /// Celestia Client websocket URL
    #[arg(short = 'c', long, env = "PRISM_CELESTIA_CLIENT")]
    pub celestia_client: Option<String>,

    /// Celestia Snark Namespace ID
    #[arg(long, env = "PRISM_SNARK_NAMESPACE_ID")]
    pub snark_namespace_id: Option<String>,

    /// Celestia Transaction Namespace ID
    #[arg(long, env = "PRISM_OPERATION_NAMESPACE_ID")]
    pub operation_namespace_id: Option<String>,

    /// Height to start searching the DA layer for SNARKs
    #[arg(short = 's', long, env = "PRISM_CELESTIA_START_HEIGHT")]
    pub celestia_start_height: Option<u64>,
}

/// Web server configuration arguments
#[derive(Args, Deserialize, Clone, Debug)]
#[group(required = false, multiple = true)]
pub struct WebserverArgs {
    /// Whether the web server should be active
    #[arg(long, env = "PRISM_WEBSERVER_ACTIVE")]
    pub webserver_active: Option<bool>,

    /// IP address for the webserver to listen on
    #[arg(long, requires = "webserver_active", default_value = "127.0.0.1", env = "PRISM_WEBSERVER_HOST")]
    pub host: Option<String>,

    /// Port number for the webserver to listen on
    #[arg(short, long, requires = "webserver_active", env = "PRISM_WEBSERVER_PORT")]
    pub port: Option<u16>,
}

/// Database configuration arguments
#[derive(Args, Deserialize, Clone, Debug)]
pub struct DatabaseArgs {
    /// Storage backend to use (rocks-db, in-memory, redis)
    #[arg(long, value_enum, default_value_t = DBValues::RocksDB, env = "PRISM_DB_TYPE")]
    pub db_type: DBValues,

    /// Directory path for the RocksDB database, used when db_type is rocks-db
    #[arg(long, required_if_eq("db_type", "rocks-db"), default_value = "data", env = "PRISM_ROCKSDB_DIRECTORY_PATH")]
    pub rocksdb_path: Option<String>,

    /// Connection string to Redis, used when db_type is redis
    #[arg(long, required_if_eq("db_type", "redis"), env = "PRISM_REDIS_URL")]
    pub redis_url: Option<String>,
}

/// Database types
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
pub enum DBValues {
    /// RocksDB storage backend
    #[default]
    RocksDB,

    /// In-memory storage backend
    InMemory,

    /// Redis storage backend
    Redis,
}
