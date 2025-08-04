use anyhow::Result;
use prism_da::LightDataAvailabilityLayer;
use prism_keys::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{env::current_dir, sync::Arc};
use tokio_util::sync::CancellationToken;

use crate::LightClient;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LightClientConfig {
    #[serde(rename = "verifying_key")]
    pub verifying_key_str: String,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        LightClientConfig {
            verifying_key_str: dirs::home_dir()
                .unwrap_or_else(|| current_dir().unwrap_or_default())
                .join(".prism/prover_key.spki")
                .to_string_lossy()
                .into_owned(),
        }
    }
}

pub fn create_light_client(
    da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
    config: &LightClientConfig,
    cancellation_token: CancellationToken,
) -> Result<LightClient> {
    let verifying_key = VerifyingKey::from_spki_pem_path_or_base64_der(&config.verifying_key_str)?;
    Ok(LightClient::new(da, verifying_key, cancellation_token))
}
