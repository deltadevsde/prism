use crate::settings::{
    models::{Settings, DALayerOption, WebServerConfig, NetworkConfig, CelestiaNetworkConfig, KeystoreConfig, KeystoreFileConfig, DatabaseConfig, RocksDBConfig, RedisConfig, CustomNetworkConfig},
    settings::SettingsBuilder,
    validation::validate_config,
    sources::apply_command_line_args,
    cli::{CommandArgs, DatabaseArgs, WebserverArgs, CelestiaArgs, DBValues},
};
use std::path::PathBuf;
use tempfile::{tempdir, TempDir};
use prism_da::celestia::utils::Network;
use toml;

/// Helper function to create a testing home directory
fn create_test_home() -> (TempDir, String) {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let home_path = temp_dir.path().to_string_lossy().to_string();
    (temp_dir, home_path)
}

/// Helper function to create a standard valid test configuration using a temporary directory
fn create_test_settings() -> (TempDir, Settings) {
    let (temp_dir, home_path) = create_test_home();
    let mut settings = Settings::initialize(&home_path, "testnet");

    // Add required Celestia config to make it valid
    settings.network.celestia_config = CelestiaNetworkConfig {
        celestia_network: "mocha".to_string(),
        connection_string: "ws://127.0.0.1:26658".to_string(),
        start_height: 1,
        snark_namespace_id: "test_snark".to_string(),
        operation_namespace_id: "test_operation".to_string(),
    };

    // Add required custom network config to make it valid
    settings.network.custom = CustomNetworkConfig {
        verifying_key: None,
        celestia_network: "mocha".to_string(),
        celestia_start_height: 1,
        snark_namespace_id: "test_snark".to_string(),
        operation_namespace_id: "test_operation".to_string(),
    };

    (temp_dir, settings)
}

// ===== VALIDATION TESTS =====

#[test]
fn test_validate_config_valid_settings() {
    // Create a minimal valid settings object
    let (_temp_dir, settings) = create_test_settings();

    // Validation should pass with no errors
    let result = validate_config(&settings);
    assert!(result.is_ok(), "Validation failed: {:?}", result.err());
}

#[test]
fn test_validate_config_invalid_webserver() {
    // Create settings with invalid webserver config
    let (_temp_dir, mut settings) = create_test_settings();
    settings.webserver = WebServerConfig {
        enabled: true,
        host: "not-an-ip-address".to_string(), // Invalid IP address
        port: 8080,
    };

    // Validation should fail
    let result = validate_config(&settings);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("IP address"), "Error message was: {}", error_msg);
}

#[test]
fn test_validate_config_celestia_without_config() {
    // This test no longer applies since CelestiaNetworkConfig is no longer optional
    // and is always created with default values
}

#[test]
fn test_validate_celestia_invalid_connection_string() {
    // Create settings with invalid Celestia connection string
    let (_temp_dir, mut settings) = create_test_settings();

    // Set invalid connection string (not a WebSocket URL)
    settings.network.celestia_config.connection_string = "invalid://127.0.0.1:26658".to_string();

    // Validation should fail
    let result = validate_config(&settings);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("WebSocket URL") || error_msg.contains("Invalid Celestia connection string format"),
        "Error message was: {}", error_msg);
}

#[test]
fn test_validate_celestia_empty_connection_string() {
    // Create settings with empty Celestia connection string
    let (_temp_dir, mut settings) = create_test_settings();

    // Set empty connection string
    settings.network.celestia_config.connection_string = "".to_string();

    // Validation should fail
    let result = validate_config(&settings);
    assert!(result.is_err());

    // The error message can be either of these, depending on the URL validation implementation
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("WebSocket URL") ||
        error_msg.contains("Invalid Celestia connection string format"),
        "Error message was: {}", error_msg
    );
}

#[test]
fn test_validate_redis_invalid_url() {
    // Create settings with invalid Redis URL
    let (_temp_dir, mut settings) = create_test_settings();

    // Set database to Redis with invalid URL
    settings.db = DatabaseConfig {
        db_type: "Redis".to_string(),
        rocksdb_config: None,
        redis_config: Some(RedisConfig {
            url: "invalid-url".to_string(),
        }),
    };

    // Validation should fail
    let result = validate_config(&settings);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Redis connection string should start with 'redis://'"),
        "Error message was: {}", error_msg);
}

#[test]
fn test_validate_keystore_invalid_type() {
    // Create settings with invalid keystore type
    let (_temp_dir, mut settings) = create_test_settings();

    // Set invalid keystore type
    settings.keystore.keystore_type = "invalid_type".to_string();

    // Validation should fail
    let result = validate_config(&settings);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Invalid keystore type"),
        "Error message was: {}", error_msg);
}

#[test]
fn test_validate_keystore_missing_path() {
    // Create settings with file keystore but missing path
    let (_temp_dir, mut settings) = create_test_settings();

    // Set keystore type to file but with empty path
    settings.keystore.keystore_type = "file".to_string();
    settings.keystore.file.file_path = "".to_string();

    // Validation should fail
    let result = validate_config(&settings);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Keystore file path must be provided"),
        "Error message was: {}", error_msg);
}

#[test]
fn test_default_values() {
    // Create settings with defaults
    let settings = Settings::initialize("", "testnet");

    // Check default values
    assert_eq!(settings.webserver.port, 0); // Default value
    assert_eq!(settings.webserver.host, "127.0.0.1"); // Default value
    assert!(settings.webserver.enabled); // Default value
}

// ===== HIERARCHY TESTS =====

#[test]
fn test_simple_merge() {
    // Create base settings
    let (_temp_dir, settings) = create_test_settings();

    // Create a settings builder with some overrides
    let mut override_map = serde_json::Map::new();
    override_map.insert("keystore".to_string(), serde_json::json!({
        "file": {
            "file_path": "/tmp/new_keystore.json"
        }
    }));
    override_map.insert("webserver".to_string(), serde_json::json!({
        "port": 9000
    }));

    let override_value = serde_json::Value::Object(override_map);
    let override_builder = SettingsBuilder::new(override_value);

    // Create a settings builder from the base settings
    let mut settings_builder = SettingsBuilder::new(settings.clone());

    // Merge the overrides
    settings_builder.merge(override_builder);

    // Convert back to Settings
    let merged = settings_builder.to_settings().unwrap();

    // Verify the overrides were applied
    assert_eq!(merged.keystore.file.file_path, "/tmp/new_keystore.json");
    assert_eq!(merged.webserver.port, 9000);

    // Verify other fields were not changed
    assert_eq!(merged.keystore.keystore_type, settings.keystore.keystore_type);
    assert_eq!(merged.webserver.host, settings.webserver.host);
}

#[test]
fn test_cli_override() {
    // Create base settings
    let (_temp_dir, settings) = create_test_settings();

    // Create CLI args with some overrides
    let args = CommandArgs {
        log_level: "DEBUG".to_string(),
        network_name: "testnet".to_string(),
        verifying_key: None,
        home_path: None,
        database: DatabaseArgs {
            db_type: DBValues::RocksDB,
            rocksdb_path: Some("/tmp/rocks".to_string()),
            redis_url: None,
        },
        keystore_type: Some("file".to_string()),
        keystore_path: Some("/tmp/keystore.json".to_string()),
        celestia: CelestiaArgs {
            celestia_client: Some("ws://new-node:26658".to_string()),
            snark_namespace_id: None,
            operation_namespace_id: None,
            celestia_start_height: Some(100),
        },
        webserver: WebserverArgs {
            webserver_active: Some(true),
            host: Some("0.0.0.0".to_string()),
            port: Some(9000),
        },
    };

    // Apply CLI overrides
    let result = apply_command_line_args(settings.clone(), args);
    assert!(result.is_ok());
    let updated = result.unwrap();

    // Verify CLI args were applied
    assert_eq!(updated.webserver.host, "0.0.0.0");
    assert_eq!(updated.webserver.port, 9000);
    assert_eq!(updated.keystore.keystore_type, "file");
    assert_eq!(updated.keystore.file.file_path, "/tmp/keystore.json");
    assert_eq!(updated.network.celestia_config.connection_string, "ws://new-node:26658");
    assert_eq!(updated.network.celestia_config.start_height, 1);
    assert_eq!(updated.network.custom.celestia_start_height, 100);
}

#[test]
fn test_merge_hierarchy() {
    // Create base settings (lowest priority)
    let (_temp_dir, home_path) = create_test_home();
    let base_settings = Settings {
        da_layer: DALayerOption::Celestia,
        keystore: KeystoreConfig {
            keystore_type: "keychain".to_string(),
            file: KeystoreFileConfig {
                file_path: PathBuf::from(&home_path).join("keystore.json").to_string_lossy().to_string(),
            },
        },
        webserver: WebServerConfig {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 8080,
        },
        network: NetworkConfig {
            network: Network::Custom("testnet".to_string()),
            network_name: "testnet".to_string(),
            verifying_key: None,
            celestia_config: CelestiaNetworkConfig {
                celestia_network: "mocha".to_string(),
                connection_string: "ws://127.0.0.1:26658".to_string(),
                start_height: 1,
                snark_namespace_id: "test_snark".to_string(),
                operation_namespace_id: "test_operation".to_string(),
            },
            custom: CustomNetworkConfig::default(),
        },
        db: DatabaseConfig {
            db_type: "RocksDB".to_string(),
            rocksdb_config: Some(RocksDBConfig {
                directory_path: PathBuf::from(&home_path).join("data").to_string_lossy().to_string(),
            }),
            redis_config: None,
        },
    };

    // Create environment settings (medium priority)
    let (_home_path2, home_path2) = create_test_home();
    let env_settings = Settings {
        da_layer: DALayerOption::Celestia,
        keystore: KeystoreConfig {
            keystore_type: "file".to_string(), // Different from base
            file: KeystoreFileConfig {
                file_path: PathBuf::from(&home_path2).join("keystore.json").to_string_lossy().to_string(),
            },
        },
        webserver: WebServerConfig {
            enabled: false, // Different from base
            host: "192.168.1.1".to_string(), // Different from base
            port: 8080, // Same as base
        },
        network: NetworkConfig {
            network: Network::Custom("testnet".to_string()),
            network_name: "testnet".to_string(),
            verifying_key: None,
            celestia_config: CelestiaNetworkConfig {
                celestia_network: "mocha".to_string(),
                connection_string: "ws://127.0.0.1:26658".to_string(),
                start_height: 1,
                snark_namespace_id: "test_snark".to_string(),
                operation_namespace_id: "test_operation".to_string(),
            },
            custom: CustomNetworkConfig::default(),
        },
        db: DatabaseConfig {
            db_type: "InMemory".to_string(), // Different
            rocksdb_config: None,
            redis_config: None,
        },
    };

    // Create builder and merge settings
    let mut builder = SettingsBuilder::new(base_settings.clone());
    let env_builder = SettingsBuilder::new(env_settings.clone());
    builder.merge(env_builder);
    let merged = builder.to_settings().unwrap();

    // Check merged values (env should override base)
    assert!(!merged.webserver.enabled); // From settings2
    assert_eq!(merged.webserver.host, "192.168.1.1"); // From settings2
    assert_eq!(merged.webserver.port, 8080); // Same in both
    assert_eq!(merged.keystore.keystore_type, "file"); // From settings2
    assert_eq!(merged.db.db_type, "InMemory"); // From settings2
}

#[test]
fn test_three_level_merge() {
    // Create base settings
    let (_temp_dir, settings) = create_test_settings();

    // Create a settings builder from the base settings
    let settings_builder = SettingsBuilder::new(settings.clone());

    // Create a first level of overrides
    let mut override_map1 = serde_json::Map::new();
    override_map1.insert("webserver".to_string(), serde_json::json!({
        "port": 9000
    }));
    override_map1.insert("network".to_string(), serde_json::json!({
        "celestia": {
            "start_height": 1000
        },
        "custom": {
            "celestia_start_height": 1000
        }
    }));
    let override_value1 = serde_json::Value::Object(override_map1);
    let override_builder1 = SettingsBuilder::new(override_value1);

    // Create a second level of overrides
    let mut override_map2 = serde_json::Map::new();
    override_map2.insert("webserver".to_string(), serde_json::json!({
        "host": "0.0.0.0"
    }));
    override_map2.insert("keystore".to_string(), serde_json::json!({
        "type": "file",
        "file": {
            "file_path": "/tmp/keystore.json"
        }
    }));
    let override_value2 = serde_json::Value::Object(override_map2);
    let override_builder2 = SettingsBuilder::new(override_value2);

    // Merge the overrides in order
    let mut merged_builder = settings_builder.clone();
    merged_builder.merge(override_builder1);
    merged_builder.merge(override_builder2);

    // Convert back to Settings
    let merged = merged_builder.to_settings().unwrap();

    // Verify the overrides were applied in the correct order
    assert_eq!(merged.webserver.port, 9000); // From override1
    assert_eq!(merged.webserver.host, "0.0.0.0"); // From override2
    assert_eq!(merged.keystore.keystore_type, "file"); // From override2
    assert_eq!(merged.keystore.file.file_path, "/tmp/keystore.json"); // From override2
    assert_eq!(merged.network.celestia_config.start_height, 1000); // From override1
    assert_eq!(merged.network.custom.celestia_start_height, 1000); // From override1
}

#[test]
fn test_cli_override_complex() {
    // Base test settings
    let (_temp_dir, base_settings) = create_test_settings();

    // Create CLI args with celestia start_height override
    let cli_args = CommandArgs {
        log_level: "INFO".to_string(),
        network_name: "testnet".to_string(),
        verifying_key: None,
        home_path: None,
        database: DatabaseArgs {
            db_type: DBValues::RocksDB,
            rocksdb_path: None,
            redis_url: None,
        },
        keystore_type: None,
        keystore_path: None,
        celestia: CelestiaArgs {
            celestia_client: None,
            snark_namespace_id: None,
            operation_namespace_id: None,
            celestia_start_height: None,
        },
        webserver: WebserverArgs {
            port: Some(7070), // Override port
            host: None, // Don't override host
            webserver_active: Some(false), // Override enabled
        },
    };

    // Apply CLI args to base settings
    let final_config = apply_command_line_args(base_settings.clone(), cli_args).unwrap();

    // Check that only the provided CLI values override base settings
    assert_eq!(final_config.webserver.port, 7070); // From CLI
    assert_eq!(final_config.webserver.host, "127.0.0.1"); // From base, not overridden
    assert!(!final_config.webserver.enabled); // From CLI

    // Check that redis type with args works correctly
    let cli_args = CommandArgs {
        log_level: "INFO".to_string(),
        network_name: "testnet".to_string(),
        verifying_key: None,
        home_path: None,
        database: DatabaseArgs {
            db_type: DBValues::Redis,
            redis_url: Some("redis://localhost:6379".to_string()),
            rocksdb_path: None,
        },
        keystore_type: None,
        keystore_path: None,
        celestia: CelestiaArgs {
            celestia_client: None,
            snark_namespace_id: None,
            operation_namespace_id: None,
            celestia_start_height: None,
        },
        webserver: WebserverArgs {
            port: None,
            host: None,
            webserver_active: None,
        },
    };

    // Apply CLI args to base settings
    let final_config = apply_command_line_args(base_settings, cli_args).unwrap();

    // Check database type and URL
    assert_eq!(final_config.db.db_type, "Redis");
    match final_config.db.redis_config {
        Some(redis_config) => {
            assert_eq!(redis_config.url, "redis://localhost:6379");
        }
        None => panic!("Redis config should be Some"),
    }

    // Check connection string
    assert_eq!(final_config.network.celestia_config.connection_string, "ws://127.0.0.1:26658");
}

#[test]
fn test_default_network() {
    // Get the default network
    let default_net = crate::settings::models::default_network();

    // Verify that the default network is "local"
    match default_net {
        Network::Custom(name) => assert_eq!(name, "local"),
        _ => panic!("Default network should be Network::Custom(\"local\")"),
    }
}

#[test]
fn test_parse_network() {
    // Test parsing known networks
    let specter = NetworkConfig::parse_network("specter");
    match specter {
        Network::Specter => {},
        _ => panic!("Expected Network::Specter"),
    }

    let devnet = NetworkConfig::parse_network("devnet");
    match devnet {
        Network::Specter => {},
        _ => panic!("Expected Network::Specter"),
    }

    // Test parsing custom network
    let custom = NetworkConfig::parse_network("mycustomnet");
    match custom {
        Network::Custom(name) => assert_eq!(name, "mycustomnet"),
        _ => panic!("Expected Network::Custom"),
    }

    // Test case insensitivity
    let specter_caps = NetworkConfig::parse_network("SPECTER");
    match specter_caps {
        Network::Specter => {},
        _ => panic!("Expected Network::Specter"),
    }
}

#[test]
fn test_network_name_field() {
    // Create a NetworkConfig with a specific network_name
    let network_config = NetworkConfig {
        network: Network::Custom("testnet".to_string()),
        network_name: "my-testnet".to_string(),
        verifying_key: None,
        celestia_config: CelestiaNetworkConfig::default(),
        custom: CustomNetworkConfig::default(),
    };

    // Verify that the network_name is preserved in the DA network config
    let da_config = network_config.to_da_network_config();
    assert_eq!(da_config.network_name, "my-testnet");
}

#[test]
fn test_verifying_key_none_serialization() {
    // Create a NetworkConfig with verifying_key set to None
    let network_config = NetworkConfig {
        network: Network::Custom("testnet".to_string()),
        network_name: "testnet".to_string(),
        verifying_key: None,
        celestia_config: CelestiaNetworkConfig::default(),
        custom: CustomNetworkConfig::default(),
    };

    // Serialize to TOML
    let toml_string = toml::to_string(&network_config).unwrap();

    // Verify that the verifying_key is serialized as an empty string
    assert!(toml_string.contains("verifying_key = \"\""));

    // Deserialize back from TOML
    let deserialized: NetworkConfig = toml::from_str(&toml_string).unwrap();

    // Verify that the verifying_key is None
    assert!(deserialized.verifying_key.is_none());
}

#[test]
fn test_verifying_key_some_serialization() {
    // Create a signing key to get a verifying key
    let signing_key = prism_keys::SigningKey::new_ed25519();
    let verifying_key = signing_key.verifying_key();

    // Create a NetworkConfig with verifying_key set to Some(verifying_key)
    let network_config = NetworkConfig {
        network: Network::Custom("testnet".to_string()),
        network_name: "testnet".to_string(),
        verifying_key: Some(verifying_key.clone()),
        celestia_config: CelestiaNetworkConfig::default(),
        custom: CustomNetworkConfig::default(),
    };

    // Serialize to TOML
    let toml_string = toml::to_string(&network_config).unwrap();

    // Verify that the verifying_key is serialized as a non-empty string
    let expected_key_string = format!("verifying_key = \"{}\"", verifying_key.to_string());
    assert!(toml_string.contains(&expected_key_string));

    // Deserialize back from TOML
    let deserialized: NetworkConfig = toml::from_str(&toml_string).unwrap();

    // Verify that the verifying_key is Some and matches the original
    assert!(deserialized.verifying_key.is_some());
    assert_eq!(deserialized.verifying_key.unwrap().to_string(), verifying_key.to_string());
}
