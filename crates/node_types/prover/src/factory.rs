use anyhow::{Result, anyhow};
use prism_da::DataAvailabilityLayer;
use prism_keys::{SigningKey, VerifyingKey};
use prism_storage::Database;
use serde::{Deserialize, Serialize};
use std::{
    env::{self},
    path::Path,
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

use crate::{
    Prover, ProverEngineOptions, ProverOptions, SequencerOptions, SyncerOptions, WebServerOptions,
    prover::DEFAULT_MAX_EPOCHLESS_GAP,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebServerConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        WebServerConfig {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 41997,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FullNodeProverConfig {
    #[serde(rename = "verifying_key")]
    pub verifying_key_str: String,
    pub webserver: WebServerConfig,
}

impl Default for FullNodeProverConfig {
    fn default() -> Self {
        FullNodeProverConfig {
            verifying_key_str: dirs::home_dir()
                .unwrap_or_else(|| env::current_dir().unwrap_or_default())
                .join(".prism/prover_key.spki")
                .to_string_lossy()
                .into_owned(),
            webserver: WebServerConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ProverProverConfig {
    pub signing_key_path: String,
    pub max_epochless_gap: u64,
    pub recursive_proofs: bool,
    pub webserver: WebServerConfig,
}

impl Default for ProverProverConfig {
    fn default() -> Self {
        ProverProverConfig {
            signing_key_path: dirs::home_dir()
                .unwrap_or_else(|| env::current_dir().unwrap_or_default())
                .join(".prism/prover_key.pk8")
                .to_string_lossy()
                .into_owned(),
            max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
            recursive_proofs: true,
            webserver: WebServerConfig::default(),
        }
    }
}

pub fn create_prover_as_full_node(
    config: &FullNodeProverConfig,
    db: Arc<Box<dyn Database>>,
    da: Arc<dyn DataAvailabilityLayer>,
    cancellation_token: CancellationToken,
) -> Result<Prover> {
    let verifying_key = VerifyingKey::from_spki_pem_path_or_base64_der(&config.verifying_key_str)?;

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
        webserver: WebServerOptions {
            enabled: config.webserver.enabled,
            host: config.webserver.host.clone(),
            port: config.webserver.port,
        },
    };

    Prover::new(db, da, &prover_opts, cancellation_token)
}

pub fn create_prover_as_prover(
    config: &ProverProverConfig,
    db: Arc<Box<dyn Database>>,
    da: Arc<dyn DataAvailabilityLayer>,
    cancellation_token: CancellationToken,
) -> Result<Prover> {
    let signing_key = SigningKey::from_pkcs8_pem_file(&config.signing_key_path)
        .or_else(|_| create_ed25519_key_pair_pem_files(&config.signing_key_path))
        .map_err(|e| anyhow!("Failed to load signing key: {}", e))?;

    let recursive_proofs =
        env::var("SP1_PROVER").map_or(config.recursive_proofs, |val| val != "mock");

    let prover_opts = ProverOptions {
        syncer: SyncerOptions {
            verifying_key: signing_key.verifying_key(),
            start_height: 1,
            max_epochless_gap: config.max_epochless_gap,
            prover_enabled: false,
        },
        sequencer: SequencerOptions {
            signing_key: Some(signing_key),
            batcher_enabled: true,
        },
        prover_engine: ProverEngineOptions { recursive_proofs },
        webserver: WebServerOptions {
            enabled: config.webserver.enabled,
            host: config.webserver.host.clone(),
            port: config.webserver.port,
        },
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
