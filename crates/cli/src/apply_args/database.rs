use anyhow::Result;
use prism_storage::{DatabaseConfig, rocksdb::RocksDBConfig};

use crate::cli_args::{CliDatabaseArgs, CliDatabaseType};

pub fn apply_database_args(config: &mut DatabaseConfig, args: &CliDatabaseArgs) -> Result<()> {
    match (config, &args.db_type) {
        (_, None) => {
            // No cli arg specified, do not modify config
            Ok(())
        }
        (DatabaseConfig::RocksDB(rocksdb_config), Some(CliDatabaseType::RocksDB)) => {
            apply_rocksdb_args(rocksdb_config, args)
        }
        (DatabaseConfig::InMemory, Some(CliDatabaseType::InMemory)) => {
            // No changes needed for InMemory DB type
            Ok(())
        }
        _ => anyhow::bail!("DB type mismatch"),
    }
}

fn apply_rocksdb_args(config: &mut RocksDBConfig, args: &CliDatabaseArgs) -> Result<()> {
    if let Some(path) = &args.rocksdb_path {
        config.path = path.clone();
    }
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::cli_args::{CliDatabaseArgs, CliDatabaseType};

    #[test]
    fn test_database_args_application() -> Result<()> {
        use crate::apply_args::database::apply_database_args;
        use prism_storage::{DatabaseConfig, rocksdb::RocksDBConfig};

        let mut config = DatabaseConfig::RocksDB(RocksDBConfig {
            path: "/old/path".to_string(),
        });

        let db_args = CliDatabaseArgs {
            db_type: Some(CliDatabaseType::RocksDB),
            rocksdb_path: Some("/new/path".to_string()),
        };

        apply_database_args(&mut config, &db_args)?;

        if let DatabaseConfig::RocksDB(rocksdb_config) = &config {
            assert_eq!(rocksdb_config.path, "/new/path");
        }

        Ok(())
    }

    #[test]
    fn test_db_type_mismatch_error() {
        use crate::apply_args::database::apply_database_args;
        use prism_storage::DatabaseConfig;

        // InMemory config with RocksDB CLI args should fail
        let mut config = DatabaseConfig::InMemory;
        let db_args = CliDatabaseArgs {
            db_type: Some(CliDatabaseType::RocksDB),
            rocksdb_path: Some("/some/path".to_string()),
        };

        let result = apply_database_args(&mut config, &db_args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DB type mismatch"));
    }
}
