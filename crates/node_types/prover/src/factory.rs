use std::{env, path::Path, sync::Arc};

use crate::{
    Prover, ProverEngineOptions, ProverOptions, SequencerOptions, SyncerOptions, WebServerOptions,
    prover::DEFAULT_MAX_EPOCHLESS_GAP,
};
use anyhow::{Result, anyhow, bail};
use prism_da::DataAvailabilityLayer;
use prism_keys::{SigningKey, VerifyingKey};
use prism_storage::Database;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
pub struct WebServerConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FullNodeProverConfig {
    #[serde(rename = "verifying_key")]
    pub verifying_key_str: String,
    pub webserver: WebServerConfig,
}

impl Default for FullNodeProverConfig {
    fn default() -> Self {
        FullNodeProverConfig {
            verifying_key_str: "~/.prism/full_node.spki".to_string(),
            webserver: WebServerConfig {
                enabled: true,
                host: "127.0.0.1".to_string(),
                port: 41997,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProverProverConfig {
    pub signing_key_path: String,
    pub max_epochless_gap: u64,
    pub recursive_proofs: bool,
    pub webserver: WebServerConfig,
}

impl Default for ProverProverConfig {
    fn default() -> Self {
        ProverProverConfig {
            signing_key_path: "~/.prism/prover.pk8".to_string(),
            max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
            recursive_proofs: false,
            webserver: WebServerConfig {
                enabled: true,
                host: "127.0.0.1".to_string(),
                port: 41997,
            },
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
    let signing_key = SigningKey::from_pkcs8_pem_path_or_create_ed25519(&config.signing_key_path)?;
    let recursive_proofs = env::var("SP1_PROVER").map_or(true, |val| val != "mock");

    let prover_opts = ProverOptions {
        syncer: SyncerOptions {
            verifying_key: signing_key.verifying_key(),
            start_height: 1,
            max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
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
