use anyhow::Result;
use prism_da::LightDataAvailabilityLayer;
use prism_keys::VerifyingKey;
use prism_serde::base64::FromBase64;
use serde::Deserialize;
use std::{path::Path, sync::Arc};
use tokio_util::sync::CancellationToken;

use crate::LightClient;

#[derive(Clone, Debug, Deserialize)]
pub struct LightClientConfig {
    #[serde(rename = "verifying_key")]
    pub verifying_key_str: String,
}

impl LightClientConfig {
    /// Load a verifying key from either a file path or base64 string.
    ///
    /// If the `verifying_key_str` looks like a file path (contains path separators
    /// or the file exists), it will attempt to load it as an SPKI PEM file.
    /// Otherwise, it will attempt to parse it as a base64-encoded key.
    pub fn load_verifying_key(&self) -> Result<VerifyingKey> {
        let key_str = &self.verifying_key_str;
        let path = Path::new(key_str);

        // Check if it's a file path by looking for path separators or file existence
        if key_str.contains('/') || key_str.contains('\\') || path.exists() {
            // Try to load as SPKI PEM file
            VerifyingKey::from_spki_pem_file(path).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to load verifying key from file '{}': {}",
                    key_str,
                    e
                )
            })
        } else {
            // Try to load as base64
            VerifyingKey::from_base64(key_str).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to load verifying key from base64 '{}': {}",
                    key_str,
                    e
                )
            })
        }
    }
}

pub fn create_light_client(
    da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
    verifying_key: VerifyingKey,
    cancellation_token: CancellationToken,
) -> Result<LightClient> {
    Ok(LightClient::new(da, verifying_key, cancellation_token))
}

pub fn create_light_client_from_config(
    da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
    config: &LightClientConfig,
    cancellation_token: CancellationToken,
) -> Result<LightClient> {
    let verifying_key = config.load_verifying_key()?;
    create_light_client(da, verifying_key, cancellation_token)
}
