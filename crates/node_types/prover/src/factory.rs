use anyhow::{Result, anyhow};
use prism_da::DataAvailabilityLayer;
use prism_keys::{SigningKey, VerifyingKey};
use prism_presets::{
    ApplyPreset, FullNodePreset, PRESET_SPECTER_PUBLIC_KEY_BASE64, PresetError, ProverPreset,
};
use prism_storage::Database;
use serde::{Deserialize, Serialize};
use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
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
    /// Path to a verifying key file or DER+base64-encoded verifying key.
    /// Used to verify SNARK proofs from provers.
    /// Default: ~/.prism/prover_key.spki
    #[serde(rename = "verifying_key")]
    pub verifying_key_str: String,

    /// Web server configuration for REST API endpoints.
    pub webserver: WebServerConfig,
}

impl Default for FullNodeConfig {
    fn default() -> Self {
        FullNodeConfig {
            verifying_key_str: dirs::home_dir()
                .or_else(|| env::current_dir().ok())
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".prism/prover_key.spki")
                .to_string_lossy()
                .into_owned(),
            webserver: WebServerConfig::default(),
        }
    }
}

impl ApplyPreset<FullNodePreset> for FullNodeConfig {
    fn apply_preset(&mut self, preset: &FullNodePreset) -> Result<(), PresetError> {
        if let FullNodePreset::Specter = preset {
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
    /// Path to the signing key file for generating proofs.
    /// If the file doesn't exist, a new key pair will be generated automatically.
    /// The private key must be kept secure as it signs SNARK proofs.
    /// Default: ~/.prism/prover_key.pk8
    pub signing_key_path: String,

    /// Maximum number of epochs without generating a proof before forcing one.
    /// Lower values provide faster finality but increase computational overhead.
    pub max_epochless_gap: u64,

    /// Whether to generate recursive SNARK proofs.
    /// Recursive proofs have constant verification time but require more computation.
    /// May be overridden by the SP1_PROVER environment variable.
    pub recursive_proofs: bool,

    /// Web server configuration for REST API endpoints.
    pub webserver: WebServerConfig,
}

impl Default for ProverConfig {
    fn default() -> Self {
        ProverConfig {
            signing_key_path: dirs::home_dir()
                .or_else(|| env::current_dir().ok())
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".prism/prover_key.pk8")
                .to_string_lossy()
                .into_owned(),
            max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
            recursive_proofs: true,
            webserver: WebServerConfig::default(),
        }
    }
}

impl ApplyPreset<ProverPreset> for ProverConfig {
    fn apply_preset(&mut self, preset: &ProverPreset) -> Result<(), PresetError> {
        if let ProverPreset::Development = preset {
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
pub fn create_prover_as_full_node(
    config: &FullNodeConfig,
    db: Arc<Box<dyn Database>>,
    da: Arc<dyn DataAvailabilityLayer>,
    cancellation_token: CancellationToken,
) -> Result<Prover> {
    let verifying_key = VerifyingKey::from_spki_pem_path_or_base64(&config.verifying_key_str)?;

    let prover_opts = ProverOptions {
        syncer: SyncerOptions {
            verifying_key,
            start_height: 1,
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

    Prover::new(db, da, &prover_opts, cancellation_token)
}

/// Creates a prover instance configured for proof generation.
///
/// This creates a prover that generates SNARK proofs, batches transactions,
/// and publishes epochs to the DA layer. Requires significant computational resources.
///
/// See the crate-level documentation for usage examples and integration patterns.
pub fn create_prover_as_prover(
    config: &ProverConfig,
    db: Arc<Box<dyn Database>>,
    da: Arc<dyn DataAvailabilityLayer>,
    cancellation_token: CancellationToken,
) -> Result<Prover> {
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

    let prover_opts = ProverOptions {
        syncer: SyncerOptions {
            verifying_key: signing_key.verifying_key(),
            start_height: 1,
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

    Prover::new(db, da, &prover_opts, cancellation_token)
}

fn create_ed25519_key_pair_pem_files(signing_key_path: impl AsRef<Path>) -> Result<SigningKey> {
    let signing_key = SigningKey::new_ed25519();
    signing_key.to_pkcs8_pem_file(&signing_key_path)?;

    let verifying_key_path = signing_key_path.as_ref().with_extension("spki");
    signing_key.verifying_key().to_spki_pem_file(verifying_key_path)?;

    Ok(signing_key)
}
