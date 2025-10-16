use anyhow::Result;
use prism_common::digest::Digest;
use prism_cross_target::tasks::TaskManager;
use prism_da::{LightDataAvailabilityLayer, VerificationKeys};
use prism_keys::VerifyingKey;
use std::{self, sync::Arc};
use tracing::{error, info};

use crate::syncer::{SyncState, Syncer};

#[allow(unused_imports)]
use sp1_verifier::Groth16Verifier;
// Embed the JSON content directly in the binary at compile time because we can't read files in
// WASM.
const EMBEDDED_KEYS_JSON: &str = include_str!("../../../../verification_keys/keys.json");

pub fn load_sp1_verifying_keys() -> Result<VerificationKeys> {
    let keys: VerificationKeys = serde_json::from_str(EMBEDDED_KEYS_JSON)?;
    Ok(keys)
}

/// A Prism light client for efficient network participation with minimal resource requirements.
///
/// ## Lifecycle
///
/// 1. **Initialization**: Created via factory methods with DA layer and verifying key
/// 2. **Backward Sync**: Searches for the most recent valid epoch on startup
/// 3. **Forward Sync**: Processes new epochs as they arrive from the DA layer
/// 4. **Event Processing**: Publishes verification results and sync status updates
///
/// Light clients are designed to be long-running and will continue processing
/// new epochs until cancelled via the provided cancellation token.
pub struct LightClient {
    #[cfg(not(target_arch = "wasm32"))]
    pub da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
    #[cfg(target_arch = "wasm32")]
    pub da: Arc<dyn LightDataAvailabilityLayer>,

    syncer: Arc<Syncer>,

    /// Task manager for background tasks
    task_manager: TaskManager,
}

#[allow(dead_code)]
impl LightClient {
    /// Creates a new light client instance.
    ///
    /// # Parameters
    /// * `da` - Data availability layer for retrieving blockchain data
    /// * `prover_pubkey` - Verifying key for the trusted prover
    /// * `mock_proof_verification` - If true, disables proof verification for testing only
    ///
    /// # Safety
    /// Setting `mock_proof_verification` to true disables cryptographic proof verification,
    /// which is a critical security mechanism. This should ONLY be used in test environments
    /// and NEVER in production code.
    pub fn new(
        #[cfg(not(target_arch = "wasm32"))] da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
        #[cfg(target_arch = "wasm32")] da: Arc<dyn LightDataAvailabilityLayer>,
        prover_pubkey: VerifyingKey,
        mock_proof_verification: bool,
    ) -> Self {
        let sp1_vkeys = load_sp1_verifying_keys().expect("Failed to load SP1 verifying keys");

        if mock_proof_verification {
            error!("PROOF VERIFICATION IS DISABLED - FOR TESTING ONLY");
        }

        let syncer = Syncer::new(
            Arc::clone(&da),
            prover_pubkey,
            sp1_vkeys,
            mock_proof_verification,
        );

        Self {
            da,
            syncer: Arc::new(syncer),
            task_manager: TaskManager::new(),
        }
    }

    pub async fn get_sync_state(&self) -> SyncState {
        self.syncer.get_sync_state().await
    }

    pub async fn start(&self) -> Result<()> {
        // Check if already started
        if self.task_manager.is_running() {
            info!("Light client already started");
            return Ok(());
        }

        info!("Starting light client");

        self.da.start().await?;

        // Start sync_incoming_heights task
        let syncer_clone = Arc::clone(&self.syncer);
        self.task_manager
            .spawn(|token| async move {
                if let Err(e) = syncer_clone.sync_incoming_heights(token.clone().into()).await {
                    error!("Syncing heights failed: {}", e);
                    token.trigger();
                }
            })
            .map_err(|e| anyhow::anyhow!("Failed to spawn sync heights task: {}", e))?;

        // Start sync_backwards task
        let syncer_clone = Arc::clone(&self.syncer);
        self.task_manager
            .spawn(|token| async move {
                if let Err(e) = syncer_clone.sync_backwards(token.clone().into()).await {
                    error!("Backwards sync failed: {}", e);
                    token.trigger();
                }
            })
            .map_err(|e| anyhow::anyhow!("Failed to spawn sync backwards task: {}", e))?;

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        self.da.stop().await?;

        self.task_manager
            .stop()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to stop task manager: {}", e))?;

        Ok(())
    }

    pub async fn get_latest_commitment(&self) -> Option<Digest> {
        self.syncer.get_latest_commitment().await
    }
}
