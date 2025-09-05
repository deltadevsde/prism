use crate::cli_args::{
    CliCelestiaLightClientStoreType, CliCelestiaNetwork, CliDaLayerArgs, CliDaLayerType,
};
use anyhow::{Result, bail};
use prism_da::{
    FullNodeDAConfig, LightClientDAConfig,
    celestia::{
        CelestiaFullNodeDAConfig, CelestiaLightClientDAConfig, CelestiaLightClientDAStoreConfig,
        CelestiaNetwork,
    },
};
use std::time::Duration;

pub fn apply_light_client_da_args(
    config: &mut LightClientDAConfig,
    args: &CliDaLayerArgs,
) -> Result<()> {
    match (config, &args.da_type) {
        (_, None) => {
            // No cli arg specified, do not modify config
            Ok(())
        }
        (LightClientDAConfig::Celestia(celestia_config), Some(CliDaLayerType::Celestia)) => {
            apply_celestia_light_client_da_args(celestia_config, args)
        }
        (LightClientDAConfig::InMemory, Some(CliDaLayerType::InMemory)) => {
            // No changes needed for InMemory DA type
            Ok(())
        }
        // If the DA type in the config doesn't match the CLI DA type, return an error
        _ => bail!("DA type mismatch"),
    }
}

fn apply_celestia_light_client_da_args(
    config: &mut CelestiaLightClientDAConfig,
    args: &CliDaLayerArgs,
) -> Result<()> {
    // Update Celestia network if provided
    if let Some(network) = &args.celestia_network {
        config.celestia_network = match network {
            CliCelestiaNetwork::Arabica => CelestiaNetwork::Arabica,
            CliCelestiaNetwork::Mocha => CelestiaNetwork::Mocha,
            CliCelestiaNetwork::Mainnet => CelestiaNetwork::Mainnet,
        };
    }

    // Update snark namespace ID if provided
    if let Some(namespace) = &args.celestia_snark_namespace_id {
        config.snark_namespace_id = namespace.clone();
    }

    // Update timeout settings if provided
    if let Some(timeout) = args.celestia_fetch_timeout {
        config.fetch_timeout = Duration::from_secs(timeout);
    }

    if let Some(retries) = args.celestia_fetch_max_retries {
        config.fetch_max_retries = retries;
    }

    if let Some(pruning_window) = args.celestia_pruning_window {
        config.pruning_window = Duration::from_secs(pruning_window);
    }

    // Update light client store if provided
    if let Some(store_type) = &args.celestia_store_type {
        match store_type {
            CliCelestiaLightClientStoreType::InMemory => {
                config.store = CelestiaLightClientDAStoreConfig::InMemory;
            }
            CliCelestiaLightClientStoreType::Disk => {
                let Some(path) = &args.celestia_disk_store_path else {
                    bail!("Missing path for Celestia light client store");
                };

                config.store = CelestiaLightClientDAStoreConfig::Disk { path: path.clone() };
            }
        }
    }
    Ok(())
}

pub fn apply_full_node_da_args(config: &mut FullNodeDAConfig, args: &CliDaLayerArgs) -> Result<()> {
    match (config, &args.da_type) {
        (_, None) => {
            // No cli arg specified, do not modify config
            Ok(())
        }
        (FullNodeDAConfig::Celestia(celestia_config), Some(CliDaLayerType::Celestia)) => {
            apply_celestia_full_node_da_args(celestia_config, args)
        }
        (FullNodeDAConfig::InMemory, Some(CliDaLayerType::InMemory)) => {
            // No changes needed for InMemory DA type
            Ok(())
        }
        // If the DA type in the config doesn't match the CLI DA type, return an error
        _ => bail!("DA type mismatch"),
    }
}

fn apply_celestia_full_node_da_args(
    config: &mut CelestiaFullNodeDAConfig,
    args: &CliDaLayerArgs,
) -> Result<()> {
    // Update URL if provided
    if let Some(url) = &args.celestia_url {
        config.url = url.clone();
    }

    // Update Celestia network if provided
    if let Some(network) = &args.celestia_network {
        config.celestia_network = match network {
            CliCelestiaNetwork::Arabica => CelestiaNetwork::Arabica,
            CliCelestiaNetwork::Mocha => CelestiaNetwork::Mocha,
            CliCelestiaNetwork::Mainnet => CelestiaNetwork::Mainnet,
        };
    }

    // Update snark namespace ID if provided
    if let Some(namespace) = &args.celestia_snark_namespace_id {
        config.snark_namespace_id = namespace.clone();
    }

    // Update operation namespace ID if provided
    if let Some(namespace) = &args.celestia_operation_namespace_id {
        config.operation_namespace_id = namespace.clone();
    }

    // Update timeout settings if provided
    if let Some(timeout) = args.celestia_fetch_timeout {
        config.fetch_timeout = Duration::from_secs(timeout);
    }

    if let Some(retries) = args.celestia_fetch_max_retries {
        config.fetch_max_retries = retries;
    }

    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::time::Duration;

    use crate::{
        apply_args::da::{apply_full_node_da_args, apply_light_client_da_args},
        cli_args::{
            CliCelestiaLightClientStoreType, CliCelestiaNetwork, CliDaLayerArgs, CliDaLayerType,
        },
    };

    use prism_da::{
        FullNodeDAConfig, LightClientDAConfig,
        celestia::{
            CelestiaFullNodeDAConfig, CelestiaLightClientDAConfig,
            CelestiaLightClientDAStoreConfig, CelestiaNetwork,
        },
    };

    #[test]
    fn test_light_client_da_args_application() -> Result<()> {
        // Test light client DA args
        let mut light_client_config = LightClientDAConfig::Celestia(CelestiaLightClientDAConfig {
            bootnodes: vec![],
            celestia_network: CelestiaNetwork::Arabica,
            snark_namespace_id: "old_namespace".to_string(),
            fetch_timeout: Duration::from_secs(30),
            fetch_max_retries: 3,
            pruning_window: Duration::from_secs(3600),
            store: CelestiaLightClientDAStoreConfig::InMemory,
        });

        let da_args = CliDaLayerArgs {
            da_type: Some(CliDaLayerType::Celestia),
            celestia_snark_namespace_id: Some("new_namespace".to_string()),
            celestia_network: Some(CliCelestiaNetwork::Mocha),
            celestia_fetch_timeout: Some(60),
            celestia_fetch_max_retries: Some(5),
            celestia_pruning_window: Some(7200),
            celestia_store_type: Some(CliCelestiaLightClientStoreType::Disk),
            celestia_disk_store_path: Some("/test/path".to_string()),
            ..Default::default()
        };

        apply_light_client_da_args(&mut light_client_config, &da_args)?;

        if let LightClientDAConfig::Celestia(config) = &light_client_config {
            assert_eq!(config.snark_namespace_id, "new_namespace");
            assert_eq!(config.celestia_network, CelestiaNetwork::Mocha);
            assert_eq!(config.fetch_timeout, Duration::from_secs(60));
            assert_eq!(config.fetch_max_retries, 5);
            assert_eq!(config.pruning_window, Duration::from_secs(7200));
            if let CelestiaLightClientDAStoreConfig::Disk { path } = &config.store {
                assert_eq!(path, "/test/path");
            } else {
                panic!("Expected disk store config");
            }
        } else {
            panic!("Expected Celestia config");
        }

        Ok(())
    }

    #[test]
    fn test_light_client_da_args_partial_override() -> Result<()> {
        let mut light_client_config = LightClientDAConfig::Celestia(CelestiaLightClientDAConfig {
            bootnodes: vec![],
            celestia_network: CelestiaNetwork::Arabica,
            snark_namespace_id: "old_namespace".to_string(),
            fetch_timeout: Duration::from_secs(30),
            fetch_max_retries: 3,
            pruning_window: Duration::from_secs(3600),
            store: CelestiaLightClientDAStoreConfig::InMemory,
        });

        // Only override some fields
        let da_args = CliDaLayerArgs {
            da_type: Some(CliDaLayerType::Celestia),
            celestia_snark_namespace_id: Some("new_namespace".to_string()),
            celestia_fetch_timeout: Some(45),
            // Leave other fields as None to test partial override
            ..Default::default()
        };

        apply_light_client_da_args(&mut light_client_config, &da_args)?;

        if let LightClientDAConfig::Celestia(config) = &light_client_config {
            // Overridden values
            assert_eq!(config.snark_namespace_id, "new_namespace");
            assert_eq!(config.fetch_timeout, Duration::from_secs(45));

            // Original values should remain unchanged
            assert_eq!(config.celestia_network, CelestiaNetwork::Arabica);
            assert_eq!(config.fetch_max_retries, 3);
            assert_eq!(config.pruning_window, Duration::from_secs(3600));
            assert!(matches!(
                config.store,
                CelestiaLightClientDAStoreConfig::InMemory
            ));
        }

        Ok(())
    }

    #[test]
    fn test_full_node_da_args_application() -> Result<()> {
        // Test full node DA args
        let mut full_node_config = FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig {
            url: "http://old:26658".to_string(),
            celestia_network: CelestiaNetwork::Arabica,
            snark_namespace_id: "old_snark".to_string(),
            operation_namespace_id: "old_op".to_string(),
            fetch_timeout: Duration::from_secs(30),
            fetch_max_retries: 3,
        });

        let da_args = CliDaLayerArgs {
            da_type: Some(CliDaLayerType::Celestia),
            celestia_url: Some("http://new:26658".to_string()),
            celestia_snark_namespace_id: Some("new_snark".to_string()),
            celestia_operation_namespace_id: Some("new_op".to_string()),
            celestia_network: Some(CliCelestiaNetwork::Mainnet),
            celestia_fetch_timeout: Some(45),
            celestia_fetch_max_retries: Some(10),
            ..Default::default()
        };

        apply_full_node_da_args(&mut full_node_config, &da_args)?;

        if let FullNodeDAConfig::Celestia(config) = &full_node_config {
            assert_eq!(config.url, "http://new:26658");
            assert_eq!(config.snark_namespace_id, "new_snark");
            assert_eq!(config.operation_namespace_id, "new_op");
            assert_eq!(config.celestia_network, CelestiaNetwork::Mainnet);
            assert_eq!(config.fetch_timeout, Duration::from_secs(45));
            assert_eq!(config.fetch_max_retries, 10);
        } else {
            panic!("Expected Celestia config");
        }

        Ok(())
    }

    #[test]
    fn test_da_type_mismatch_error() {
        // InMemory config with Celestia CLI args should fail
        let mut config = LightClientDAConfig::InMemory;
        let da_args = CliDaLayerArgs {
            da_type: Some(CliDaLayerType::Celestia),
            celestia_snark_namespace_id: Some("namespace".to_string()),
            ..Default::default()
        };

        let result = apply_light_client_da_args(&mut config, &da_args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DA type mismatch"));
    }

    #[test]
    fn test_full_node_da_type_mismatch_error() {
        // InMemory config with Celestia CLI args should fail
        let mut config = FullNodeDAConfig::InMemory;
        let da_args = CliDaLayerArgs {
            da_type: Some(CliDaLayerType::Celestia),
            celestia_url: Some("http://example:26658".to_string()),
            ..Default::default()
        };

        let result = apply_full_node_da_args(&mut config, &da_args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DA type mismatch"));
    }

    #[test]
    fn test_no_da_type_specified() -> Result<()> {
        // When no DA type is specified in CLI args, config should remain unchanged
        let original_config = LightClientDAConfig::Celestia(CelestiaLightClientDAConfig {
            bootnodes: vec![],
            celestia_network: CelestiaNetwork::Arabica,
            snark_namespace_id: "original_namespace".to_string(),
            fetch_timeout: Duration::from_secs(30),
            fetch_max_retries: 3,
            pruning_window: Duration::from_secs(3600),
            store: CelestiaLightClientDAStoreConfig::InMemory,
        });

        let mut config = original_config.clone();
        let da_args = CliDaLayerArgs {
            da_type: None, // No DA type specified
            celestia_snark_namespace_id: Some("should_not_be_applied".to_string()),
            ..Default::default()
        };

        apply_light_client_da_args(&mut config, &da_args)?;

        // Config should remain unchanged when no DA type is specified
        if let (LightClientDAConfig::Celestia(config), LightClientDAConfig::Celestia(original)) =
            (&config, &original_config)
        {
            assert_eq!(config.snark_namespace_id, original.snark_namespace_id);
            assert_eq!(config.celestia_network, original.celestia_network);
            assert_eq!(config.fetch_timeout, original.fetch_timeout);
        }

        Ok(())
    }

    #[test]
    fn test_in_memory_da_config() -> Result<()> {
        // Test that InMemory DA config works correctly
        let mut config = LightClientDAConfig::InMemory;
        let da_args = CliDaLayerArgs {
            da_type: Some(CliDaLayerType::InMemory),
            // Other celestia-specific args should be ignored
            celestia_snark_namespace_id: Some("should_be_ignored".to_string()),
            ..Default::default()
        };

        apply_light_client_da_args(&mut config, &da_args)?;

        // Should remain InMemory
        assert!(matches!(config, LightClientDAConfig::InMemory));

        Ok(())
    }

    #[test]
    fn test_celestia_store_type_disk_without_path_error() {
        let mut config = LightClientDAConfig::Celestia(CelestiaLightClientDAConfig {
            bootnodes: vec![],
            celestia_network: CelestiaNetwork::Arabica,
            snark_namespace_id: "namespace".to_string(),
            fetch_timeout: Duration::from_secs(30),
            fetch_max_retries: 3,
            pruning_window: Duration::from_secs(3600),
            store: CelestiaLightClientDAStoreConfig::InMemory,
        });

        // Disk store type without path should fail
        let da_args = CliDaLayerArgs {
            da_type: Some(CliDaLayerType::Celestia),
            celestia_store_type: Some(CliCelestiaLightClientStoreType::Disk),
            celestia_disk_store_path: None, // Missing required path
            ..Default::default()
        };

        let result = apply_light_client_da_args(&mut config, &da_args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing path"));
    }
}
