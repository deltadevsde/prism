use anyhow::{Result, anyhow};
use prism_da::{FullNodeDAConfig, create_full_node_da_layer};
use prism_events::EventChannel;
use prism_keys::{SigningKey, VerifyingKey};
use prism_presets::{
    ApplyPreset, FullNodePreset, PRESET_SPECTER_PUBLIC_KEY_BASE64, PresetError, ProverPreset,
};
use prism_storage::{DatabaseConfig, create_storage};
use serde::{Deserialize, Serialize};
use std::{
    env,
    path::{Path, PathBuf},
};
use tracing::info;

use crate::{
    Prover,
    prover::{
        DEFAULT_MAX_EPOCHLESS_GAP, ProverEngineOptions, ProverOptions, SequencerOptions,
        SyncerOptions,
    },
    webserver::WebServerConfig,
};

/// Configuration for Prism full nodes.
///
/// Full nodes validate state but do not generate proofs themselves.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FullNodeConfig {
    /// Database configuration for the full node
    pub db: DatabaseConfig,
    /// Data Availability configuration for the full node
    pub da: FullNodeDAConfig,

    /// Path to a verifying key file or DER+base64-encoded verifying key.
    /// Used to verify SNARK proofs from provers.
    /// Default: `~/.prism/prover_key.spki`
    #[serde(rename = "verifying_key")]
    pub verifying_key_str: String,

    /// Height of the first block with prism information.
    /// Default: 1
    pub start_height: u64,

    /// Web server configuration for REST API endpoints.
    pub webserver: WebServerConfig,
}

impl Default for FullNodeConfig {
    fn default() -> Self {
        Self {
            db: DatabaseConfig::default(),
            da: FullNodeDAConfig::default(),
            verifying_key_str: dirs::home_dir()
                .or_else(|| env::current_dir().ok())
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".prism/prover_key.spki")
                .to_string_lossy()
                .into_owned(),
            start_height: 1,
            webserver: WebServerConfig::default(),
        }
    }
}

impl ApplyPreset<FullNodePreset> for FullNodeConfig {
    fn apply_preset(&mut self, preset: &FullNodePreset) -> Result<(), PresetError> {
        self.db.apply_preset(preset)?;
        self.da.apply_preset(preset)?;
        if matches!(preset, FullNodePreset::Specter) {
            self.verifying_key_str = PRESET_SPECTER_PUBLIC_KEY_BASE64.to_string();
        }
        Ok(())
    }
}

/// Configuration for Prism prover nodes.
///
/// Contains parameters for proof generation, signing keys, and batch processing.
/// Prover nodes generate SNARK proofs and publish them to the DA layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ProverConfig {
    /// Database configuration for the prover
    pub db: DatabaseConfig,
    /// Data Availability configuration for the prover
    pub da: FullNodeDAConfig,

    /// Path to the signing key file for generating proofs.
    /// If the file doesn't exist, a new key pair will be generated automatically.
    /// The private key must be kept secure as it signs SNARK proofs.
    /// Default: `~/.prism/prover_key.p8`
    pub signing_key_path: String,

    /// Height of the first block with prism information.
    /// Default: 1
    pub start_height: u64,

    /// Maximum number of epochs without generating a proof before forcing one.
    /// Lower values provide faster finality but increase computational overhead.
    pub max_epochless_gap: u64,

    /// Whether to generate recursive SNARK proofs.
    /// Recursive proofs have constant verification time but require more computation.
    /// May be overridden by the `SP1_PROVER` environment variable.
    pub recursive_proofs: bool,

    /// Web server configuration for REST API endpoints.
    pub webserver: WebServerConfig,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            da: FullNodeDAConfig::default(),
            db: DatabaseConfig::default(),
            signing_key_path: dirs::home_dir()
                .or_else(|| env::current_dir().ok())
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".prism/prover_key.p8")
                .to_string_lossy()
                .into_owned(),
            max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
            recursive_proofs: true,
            start_height: 1,
            webserver: WebServerConfig::default(),
        }
    }
}

impl ApplyPreset<ProverPreset> for ProverConfig {
    fn apply_preset(&mut self, preset: &ProverPreset) -> Result<(), PresetError> {
        self.db.apply_preset(preset)?;
        self.da.apply_preset(preset)?;
        if matches!(preset, ProverPreset::Development) {
            self.recursive_proofs = false;
        }
        Ok(())
    }
}

/// Creates a prover instance configured as a full node.
///
/// This creates a non-proving prover that validates state and serves queries
/// but does not generate SNARK proofs. Suitable for API servers and monitoring.
///
/// See the crate-level documentation for usage examples and integration patterns.
pub async fn create_prover_as_full_node(config: &FullNodeConfig) -> Result<Prover> {
    let verifying_key = VerifyingKey::from_spki_pem_path_or_base64(&config.verifying_key_str)?;
    let event_channel = EventChannel::new();

    let db = create_storage(&config.db).await?;
    let da = create_full_node_da_layer(&config.da, event_channel.clone()).await?;

    let prover_opts = ProverOptions {
        syncer: SyncerOptions {
            verifying_key,
            start_height: config.start_height,
            max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
            prover_enabled: false,
        },
        sequencer: SequencerOptions {
            signing_key: None,
            batcher_enabled: true,
        },
        prover_engine: ProverEngineOptions {
            recursive_proofs: true,
        },
        webserver: config.webserver.clone(),
    };

    Prover::new(db, da, event_channel, &prover_opts)
}

/// Creates a prover instance configured for proof generation.
///
/// This creates a prover that generates SNARK proofs, batches transactions,
/// and publishes epochs to the DA layer. Requires significant computational resources.
///
/// See the crate-level documentation for usage examples and integration patterns.
pub async fn create_prover_as_prover(config: &ProverConfig) -> Result<Prover> {
    let signing_key = SigningKey::from_pkcs8_pem_file(&config.signing_key_path)
        .or_else(|_| {
            info!(
                "Signing key not found at '{}', generating new Ed25519 key pair",
                &config.signing_key_path
            );
            create_ed25519_key_pair_pem_files(&config.signing_key_path)
        })
        .map_err(|e| anyhow!("Failed to load signing key: {}", e))?;

    let recursive_proofs =
        env::var("SP1_PROVER").map_or(config.recursive_proofs, |val| val != "mock");

    let event_channel = EventChannel::new();

    let db = create_storage(&config.db).await?;
    let da = create_full_node_da_layer(&config.da, event_channel.clone()).await?;

    let prover_opts = ProverOptions {
        syncer: SyncerOptions {
            verifying_key: signing_key.verifying_key(),
            start_height: config.start_height,
            max_epochless_gap: config.max_epochless_gap,
            prover_enabled: true,
        },
        sequencer: SequencerOptions {
            signing_key: Some(signing_key),
            batcher_enabled: true,
        },
        prover_engine: ProverEngineOptions { recursive_proofs },
        webserver: config.webserver.clone(),
    };

    Prover::new(db, da, event_channel, &prover_opts)
}

fn create_ed25519_key_pair_pem_files(signing_key_path: impl AsRef<Path>) -> Result<SigningKey> {
    let signing_key = SigningKey::new_ed25519();
    signing_key.to_pkcs8_pem_file(&signing_key_path)?;

    let verifying_key_path = signing_key_path.as_ref().with_extension("spki");
    signing_key.verifying_key().to_spki_pem_file(verifying_key_path)?;

    Ok(signing_key)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use prism_keys::SigningKey;
    use prism_presets::{
        ApplyPreset, FullNodePreset, PRESET_SPECTER_PUBLIC_KEY_BASE64, ProverPreset,
    };
    use tempfile::TempDir;

    use crate::{
        FullNodeConfig, ProverConfig, WebServerConfig, create_prover_as_full_node,
        create_prover_as_prover, prover::DEFAULT_MAX_EPOCHLESS_GAP,
    };

    #[test]
    fn test_full_node_config_default() {
        let config = FullNodeConfig::default();

        assert!(config.verifying_key_str.contains(".prism/prover_key.spki"));
        assert_eq!(config.webserver, WebServerConfig::default());
    }

    #[test]
    fn test_full_node_config_apply_specter_preset() {
        let mut config = FullNodeConfig::default();
        let result = config.apply_preset(&FullNodePreset::Specter);

        assert!(result.is_ok());
        assert_eq!(config.verifying_key_str, PRESET_SPECTER_PUBLIC_KEY_BASE64);
    }

    #[test]
    fn test_full_node_config_apply_development_preset() {
        let mut config = FullNodeConfig::default();
        let result = config.apply_preset(&FullNodePreset::Development);

        assert!(result.is_ok());
        assert_eq!(config.webserver, WebServerConfig::default());
    }

    #[test]
    fn test_prover_config_default() {
        let config = ProverConfig::default();

        assert!(config.signing_key_path.contains(".prism/prover_key.p8"));
        assert_eq!(config.max_epochless_gap, DEFAULT_MAX_EPOCHLESS_GAP);
        assert!(config.recursive_proofs);
        assert_eq!(config.webserver, WebServerConfig::default());
    }

    #[test]
    fn test_prover_config_apply_development_preset() {
        let mut config = ProverConfig::default();
        let result = config.apply_preset(&ProverPreset::Development);

        assert!(result.is_ok());
        assert!(!config.recursive_proofs); // Development preset disables recursive proofs
    }

    #[test]
    fn test_prover_config_apply_specter_preset() {
        let mut config = ProverConfig::default();
        let result = config.apply_preset(&ProverPreset::Specter);

        assert!(result.is_ok());
        // Specter preset doesn't change prover config
        assert!(config.recursive_proofs);
    }

    #[tokio::test]
    async fn test_create_prover_as_full_node() {
        let config = FullNodeConfig {
            verifying_key_str: PRESET_SPECTER_PUBLIC_KEY_BASE64.to_string(),
            ..FullNodeConfig::default()
        };

        let result = create_prover_as_full_node(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_prover_as_full_node_with_invalid_key() {
        let config = FullNodeConfig {
            verifying_key_str: "invalid_key".to_string(),
            ..FullNodeConfig::default()
        };

        let result = create_prover_as_full_node(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_prover_as_prover_with_existing_key() {
        let temp_dir = TempDir::new().unwrap();
        let signing_key_path = temp_dir.path().join("test_key.p8");

        // Create a key pair first
        let signing_key = SigningKey::new_ed25519();
        signing_key.to_pkcs8_pem_file(&signing_key_path).unwrap();

        let config = ProverConfig {
            signing_key_path: signing_key_path.to_string_lossy().to_string(),
            ..ProverConfig::default()
        };

        let result = create_prover_as_prover(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_prover_as_prover_generates_new_key() {
        let temp_dir = TempDir::new().unwrap();
        let signing_key_path = temp_dir.path().join("new_key.p8");

        let config = ProverConfig {
            signing_key_path: signing_key_path.to_string_lossy().to_string(),
            ..ProverConfig::default()
        };

        let result = create_prover_as_prover(&config).await;
        assert!(result.is_ok());

        // Verify key files were created
        assert!(signing_key_path.exists());
        assert!(signing_key_path.with_extension("spki").exists());
    }

    #[test]
    fn test_full_node_config_clone() {
        let config = FullNodeConfig {
            verifying_key_str: "test_key".to_string(),
            start_height: 10,
            ..FullNodeConfig::default()
        };

        let cloned = config.clone();
        assert_eq!(config.verifying_key_str, cloned.verifying_key_str);
        assert_eq!(config.start_height, cloned.start_height);
    }

    #[test]
    fn test_prover_config_clone() {
        let config = ProverConfig {
            signing_key_path: "test_path".to_string(),
            max_epochless_gap: 100,
            recursive_proofs: false,
            start_height: 10,
            ..ProverConfig::default()
        };

        let cloned = config.clone();
        assert_eq!(config.signing_key_path, cloned.signing_key_path);
        assert_eq!(config.max_epochless_gap, cloned.max_epochless_gap);
        assert_eq!(config.recursive_proofs, cloned.recursive_proofs);
        assert_eq!(config.start_height, cloned.start_height);
    }
}
