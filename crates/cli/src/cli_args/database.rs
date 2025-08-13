use clap::{Args, ValueEnum};
use serde::Deserialize;

#[derive(ValueEnum, Debug, Clone, Deserialize)]
pub enum CliDatabaseType {
    InMemory,
    RocksDB,
}

#[derive(Args, Clone, Debug, Default, Deserialize)]
pub struct CliDatabaseArgs {
    #[arg(long, value_enum)]
    /// Storage backend to use. Default: `rocks-db`
    pub db_type: Option<CliDatabaseType>,

    /// Path to the RocksDB database, used when `db_type` is `rocks-db`
    #[arg(long)]
    pub rocksdb_path: Option<String>,
}
