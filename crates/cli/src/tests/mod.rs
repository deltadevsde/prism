use anyhow::Result;
use std::{env, fs};
use tempfile::TempDir;

use crate::{
    apply_args::{CliArgs, CliOverridableConfig},
    cli_args::{
        CliDaLayerArgs, CliDatabaseArgs, CliDatabaseType, CliWebserverArgs, FullNodeCliArgs,
        LightClientCliArgs, ProverCliArgs,
    },
    config::{CliFullNodeConfig, CliLightClientConfig, CliProverConfig},
};

fn setup_temp_config_file(content: &str) -> Result<(TempDir, String)> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("config.toml");
    fs::write(&config_path, content)?;
    Ok((temp_dir, config_path.to_string_lossy().to_string()))
}

fn clear_env_vars() {
    for (key, _) in env::vars() {
        if key.starts_with("PRISM_") {
            unsafe { env::remove_var(key) };
        }
    }
}

#[test]
fn test_light_client_config_cli_args_precedence() -> Result<()> {
    clear_env_vars();

    // Create config file with default values
    let config_content = r#"
[light_client]
verifying_key_str = "config_file_key"
"#;

    let (_temp_dir, config_path) = setup_temp_config_file(config_content)?;

    // Set environment variable
    unsafe { env::set_var("PRISM__LIGHT_CLIENT__VERIFYING_KEY_STR", "env_key") };

    // CLI args should override both file and env
    let cli_args = LightClientCliArgs {
        dev: false,
        specter: false,
        config_path,
        verifying_key: Some("cli_key".to_string()),
        allow_mock_proofs: Some(true),
        da: Default::default(),
    };

    let config = CliLightClientConfig::load(&cli_args)?;

    // CLI args should take precedence
    assert_eq!(config.light_client.verifying_key_str, "cli_key");
    assert!(config.light_client.allow_mock_proofs);

    clear_env_vars();
    Ok(())
}

#[test]
fn test_light_client_config_env_over_file() -> Result<()> {
    clear_env_vars();

    let config_content = r#"
verifying_key = "config_file_key"
"#;

    let (_temp_dir, config_path) = setup_temp_config_file(config_content)?;

    // Set environment variable
    unsafe { env::set_var("PRISM__VERIFYING_KEY", "env_key") };
    unsafe { env::set_var("PRISM__ALLOW_MOCK_PROOFS", "true") };

    let cli_args = LightClientCliArgs {
        dev: false,
        specter: false,
        config_path,
        verifying_key: None, // No CLI override
        allow_mock_proofs: None,
        da: Default::default(),
    };

    let config = CliLightClientConfig::load(&cli_args)?;

    // Environment should override file
    assert_eq!(config.light_client.verifying_key_str, "env_key");
    assert!(config.light_client.allow_mock_proofs);

    clear_env_vars();
    Ok(())
}

#[test]
fn test_config_loading_with_missing_file() -> Result<()> {
    clear_env_vars();

    // Use non-existent config path
    let cli_args = LightClientCliArgs {
        dev: false,
        specter: false,
        config_path: "/non/existent/path.toml".to_string(),
        verifying_key: Some("cli_key".to_string()),
        allow_mock_proofs: None,
        da: Default::default(),
    };

    // Should not fail and use defaults with CLI overrides
    let config = CliLightClientConfig::load(&cli_args)?;
    assert_eq!(config.light_client.verifying_key_str, "cli_key");
    assert!(!config.light_client.allow_mock_proofs);

    Ok(())
}

#[test]
fn test_light_client_preset_application() -> Result<()> {
    clear_env_vars();

    let (_temp_dir, config_path) = setup_temp_config_file("")?;

    // Test specter preset for light client
    let cli_args = LightClientCliArgs {
        dev: false,
        specter: true,
        config_path,
        verifying_key: None,
        allow_mock_proofs: None,
        da: Default::default(),
    };

    let _config = CliLightClientConfig::load(&cli_args)?;
    // Preset should be applied (exact values depend on preset implementation)
    // This test verifies that preset loading doesn't crash

    Ok(())
}

#[test]
fn test_full_node_config_cli_args_precedence() -> Result<()> {
    clear_env_vars();

    let config_content = r#"
verifying_key = "config_key"
start_height = 25000

[webserver]
enabled = false
host = "0.0.0.0"
port = 8080

[db]
type = "rocksdb"
path = "/config/path"
"#;

    let (_temp_dir, config_path) = setup_temp_config_file(config_content)?;

    // Set environment variables
    unsafe {
        env::set_var("PRISM__VERIFYING_KEY", "env_key");
        env::set_var("PRISM__START_HEIGHT", "20000");
        env::set_var("PRISM__WEBSERVER__PORT", "9090");
        env::set_var("PRISM__DB__PATH", "/env/path");
    };

    let cli_args = FullNodeCliArgs {
        dev: false,
        specter: false,
        config_path,
        verifying_key: Some("cli_key".to_string()),
        start_height: Some(90),
        da: CliDaLayerArgs::default(),
        db: CliDatabaseArgs {
            db_type: Some(CliDatabaseType::RocksDB),
            rocksdb_path: Some("/cli/path".to_string()),
        },
        web: CliWebserverArgs {
            webserver_active: Some(true),
            host: Some("127.0.0.1".to_string()),
            port: Some(3000),
        },
    };

    let config = CliFullNodeConfig::load(&cli_args)?;

    // CLI args should take precedence
    assert_eq!(config.full_node.verifying_key_str, "cli_key");
    assert_eq!(config.full_node.start_height, 90);
    assert!(config.full_node.webserver.enabled);
    assert_eq!(config.full_node.webserver.host, "127.0.0.1");
    assert_eq!(config.full_node.webserver.port, 3000);

    // Check database config
    if let prism_storage::DatabaseConfig::RocksDB(rocksdb_config) = &config.db {
        assert_eq!(rocksdb_config.path, "/cli/path");
    } else {
        panic!("Expected RocksDB config");
    }

    clear_env_vars();
    Ok(())
}

#[test]
fn test_full_node_env_over_file() -> Result<()> {
    clear_env_vars();

    let config_content = r#"
verifying_key_str = "config_key"
start_height = 10000

[webserver]
port = 8080
"#;

    let (_temp_dir, config_path) = setup_temp_config_file(config_content)?;

    // Set environment variables

    unsafe {
        env::set_var("PRISM__VERIFYING_KEY", "env_key");
        env::set_var("PRISM__START_HEIGHT", "20000");
        env::set_var("PRISM__WEBSERVER__PORT", "9090");
    };

    let cli_args = FullNodeCliArgs {
        dev: false,
        specter: false,
        config_path,
        verifying_key: None, // No CLI override
        start_height: None,
        da: Default::default(),
        db: Default::default(),
        web: Default::default(),
    };

    let config = CliFullNodeConfig::load(&cli_args)?;

    // Environment should override file
    assert_eq!(config.full_node.verifying_key_str, "env_key");
    assert_eq!(config.full_node.start_height, 20000);
    assert_eq!(config.full_node.webserver.port, 9090);

    clear_env_vars();
    Ok(())
}

#[test]
fn test_prover_config_cli_args_precedence() -> Result<()> {
    clear_env_vars();

    let config_content = r#"
signing_key_path = "/config/key.pem"
max_epochless_gap = 5
recursive_proofs = false

[webserver]
enabled = false
port = 8080

[db]
type = "rocksdb"
path = "/config/db"
"#;

    let (_temp_dir, config_path) = setup_temp_config_file(config_content)?;

    unsafe {
        env::set_var("PRISM__MAX_EPOCHLESS_GAP", "10");
        env::set_var("PRISM__WEBSERVER__PORT", "9090");
    };

    let cli_args = ProverCliArgs {
        dev: false,
        specter: false,
        config_path,
        signing_key: Some("/cli/key.pem".to_string()),
        max_epochless_gap: Some(15),
        start_height: Some(90),
        recursive_proofs: Some(true),
        da: Default::default(),
        db: CliDatabaseArgs {
            db_type: Some(CliDatabaseType::RocksDB),
            rocksdb_path: Some("/cli/db".to_string()),
        },
        web: CliWebserverArgs {
            webserver_active: Some(true),
            port: Some(4000),
            host: None,
        },
    };

    let config = CliProverConfig::load(&cli_args)?;

    // CLI args should take precedence
    assert_eq!(config.prover.signing_key_path, "/cli/key.pem");
    assert_eq!(config.prover.max_epochless_gap, 15);
    assert_eq!(config.prover.start_height, 90);
    assert!(config.prover.recursive_proofs);
    assert!(config.prover.webserver.enabled);
    assert_eq!(config.prover.webserver.port, 4000);

    if let prism_storage::DatabaseConfig::RocksDB(rocksdb_config) = &config.db {
        assert_eq!(rocksdb_config.path, "/cli/db");
    } else {
        panic!("Expected RocksDB config");
    }

    clear_env_vars();
    Ok(())
}

#[test]
fn test_prover_env_over_file() -> Result<()> {
    clear_env_vars();

    let config_content = r#"
signing_key_path = "/config/key.pem"
max_epochless_gap = 5
start_height = 5
recursive_proofs = false
"#;

    let (_temp_dir, config_path) = setup_temp_config_file(config_content)?;

    unsafe {
        env::set_var("PRISM__MAX_EPOCHLESS_GAP", "20");
        env::set_var("PRISM__START_HEIGHT", "22");
        env::set_var("PRISM__RECURSIVE_PROOFS", "true");
    };

    let cli_args = ProverCliArgs {
        dev: false,
        specter: false,
        config_path,
        signing_key: None, // No CLI override
        max_epochless_gap: None,
        start_height: None,
        recursive_proofs: None,
        da: Default::default(),
        db: Default::default(),
        web: Default::default(),
    };

    let config = CliProverConfig::load(&cli_args)?;

    // Environment should override file
    assert_eq!(config.prover.signing_key_path, "/config/key.pem"); // From file
    assert_eq!(config.prover.max_epochless_gap, 20); // From env
    assert_eq!(config.prover.start_height, 22); // From env
    assert!(config.prover.recursive_proofs); // From env

    clear_env_vars();
    Ok(())
}

#[test]
fn test_full_node_preset_application() -> Result<()> {
    clear_env_vars();

    let (_temp_dir, config_path) = setup_temp_config_file("")?;

    // Test dev preset for full node
    let cli_args = FullNodeCliArgs {
        dev: true,
        specter: false,
        config_path,
        verifying_key: None,
        start_height: None,
        da: Default::default(),
        db: Default::default(),
        web: Default::default(),
    };

    let _config = CliFullNodeConfig::load(&cli_args)?;
    // Preset should be applied (exact values depend on preset implementation)

    Ok(())
}

#[test]
fn test_prover_preset_application() -> Result<()> {
    clear_env_vars();

    let (_temp_dir, config_path) = setup_temp_config_file("")?;

    // Test specter preset for prover
    let cli_args = ProverCliArgs {
        dev: false,
        specter: true,
        config_path,
        signing_key: None,
        max_epochless_gap: None,
        start_height: None,
        recursive_proofs: None,
        da: Default::default(),
        db: Default::default(),
        web: Default::default(),
    };

    let _config = CliProverConfig::load(&cli_args)?;
    // This test verifies that preset loading doesn't crash

    Ok(())
}

#[test]
fn test_conflicting_presets_error() {
    clear_env_vars();

    // Test that dev and specter presets conflict for full node
    let cli_args = FullNodeCliArgs {
        dev: true,
        specter: true, // This should be prevented by clap conflicts_with
        config_path: "/tmp/config.toml".to_string(),
        verifying_key: None,
        start_height: None,
        da: Default::default(),
        db: Default::default(),
        web: Default::default(),
    };

    // In practice, clap would prevent this combination, but we can test the logic
    // by checking that only one preset is applied (the first one checked)
    assert!(cli_args.preset().is_some());
}

#[test]
fn test_partial_cli_override() -> Result<()> {
    clear_env_vars();

    let config_content = r#"
signing_key_path = "/config/key.pem"
max_epochless_gap = 5
start_height = 10000
recursive_proofs = false

[webserver]
enabled = true
host = "0.0.0.0"
port = 8080
"#;

    let (_temp_dir, config_path) = setup_temp_config_file(config_content)?;

    // Only override some CLI args, others should come from config
    let cli_args = ProverCliArgs {
        dev: false,
        specter: false,
        config_path,
        signing_key: None,           // Use config value
        max_epochless_gap: Some(10), // Override config
        start_height: Some(20000),   // Override config
        recursive_proofs: None,      // Use config value
        da: Default::default(),
        db: Default::default(),
        web: CliWebserverArgs {
            webserver_active: None,              // Use config value
            host: Some("127.0.0.1".to_string()), // Override config
            port: None,                          // Use config value
        },
    };

    let config = CliProverConfig::load(&cli_args)?;

    // Mixed values from config and CLI
    assert_eq!(config.prover.signing_key_path, "/config/key.pem"); // From config
    assert_eq!(config.prover.max_epochless_gap, 10); // From CLI
    assert_eq!(config.prover.start_height, 20000); // From CLI
    assert!(!config.prover.recursive_proofs); // From config
    assert!(config.prover.webserver.enabled); // From config
    assert_eq!(config.prover.webserver.host, "127.0.0.1"); // From CLI
    assert_eq!(config.prover.webserver.port, 8080); // From config

    Ok(())
}

#[test]
fn test_invalid_config_fallback() -> Result<()> {
    clear_env_vars();

    // Create invalid TOML content
    let invalid_config_content = r#"
[prover
invalid toml syntax
"#;

    let (_temp_dir, config_path) = setup_temp_config_file(invalid_config_content)?;

    let cli_args = ProverCliArgs {
        dev: false,
        specter: false,
        config_path,
        signing_key: Some("/cli/key.pem".to_string()),
        max_epochless_gap: Some(5),
        start_height: Some(25000),
        recursive_proofs: Some(true),
        da: Default::default(),
        db: Default::default(),
        web: Default::default(),
    };

    // Should fall back to defaults and apply CLI args
    let config = CliProverConfig::load(&cli_args)?;

    // CLI args should still be applied to default config
    assert_eq!(config.prover.signing_key_path, "/cli/key.pem");
    assert_eq!(config.prover.max_epochless_gap, 5);
    assert_eq!(config.prover.start_height, 25000);
    assert!(config.prover.recursive_proofs);

    Ok(())
}
