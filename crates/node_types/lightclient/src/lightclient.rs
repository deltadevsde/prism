use anyhow::Result;
use prism_common::digest::Digest;
use prism_cross_target::tasks::{JoinHandle, spawn};
use prism_da::{LightDataAvailabilityLayer, VerificationKeys};
use prism_keys::VerifyingKey;
use std::{
    self,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;
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
    cancellation_token: CancellationToken,

    /// Task handles for sync operations
    sync_incoming_heights_handle: Arc<Mutex<Option<JoinHandle>>>,
    sync_backwards_handle: Arc<Mutex<Option<JoinHandle>>>,
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
        let cancellation_token = CancellationToken::new();

        if mock_proof_verification {
            error!("PROOF VERIFICATION IS DISABLED - FOR TESTING ONLY");
        }

        let syncer = Syncer::new(
            Arc::clone(&da),
            prover_pubkey,
            sp1_vkeys,
            cancellation_token.child_token(),
            mock_proof_verification,
        );

        Self {
            da,
            syncer: Arc::new(syncer),
            cancellation_token,
            sync_incoming_heights_handle: Arc::new(Mutex::new(None)),
            sync_backwards_handle: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn get_sync_state(&self) -> SyncState {
        self.syncer.get_sync_state().await
    }

    pub async fn start(&self) -> Result<()> {
        // Check if already started
        {
            let sync_incoming_guard = self
                .sync_incoming_heights_handle
                .lock()
                .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            let sync_backwards_guard = self
                .sync_backwards_handle
                .lock()
                .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

            if sync_incoming_guard.is_some() || sync_backwards_guard.is_some() {
                info!("Light client already started");
                return Ok(());
            }
        }

        info!("Starting light client");

        self.da.start().await?;

        // Start sync_incoming_heights task
        let syncer_clone = Arc::clone(&self.syncer);
        let sync_heights_handle = spawn(async move {
            if let Err(e) = syncer_clone.sync_incoming_heights().await {
                error!("Syncing heights failed: {}", e);
            }
        });

        // Start sync_backwards task
        let syncer_clone = Arc::clone(&self.syncer);
        let sync_backwards_handle = spawn(async move {
            if let Err(e) = syncer_clone.sync_backwards().await {
                error!("Backwards sync failed: {}", e);
            }
        });

        // Store handles
        {
            let mut sync_incoming_guard = self
                .sync_incoming_heights_handle
                .lock()
                .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            *sync_incoming_guard = Some(sync_heights_handle);
        }

        {
            let mut sync_backwards_guard = self
                .sync_backwards_handle
                .lock()
                .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            *sync_backwards_guard = Some(sync_backwards_handle);
        }

        Ok(())
    }
    async fn join_syncer_tasks(&self) -> Result<()> {
        let sync_incoming_handle = self
            .sync_incoming_heights_handle
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?
            .take();

        let sync_backwards_handle = self
            .sync_backwards_handle
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?
            .take();

        if let Some(handle) = sync_incoming_handle {
            let _ = handle.join().await;
        }

        if let Some(handle) = sync_backwards_handle {
            let _ = handle.join().await;
        }

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        self.cancellation_token.cancel();
        self.da.stop().await?;

        self.join_syncer_tasks().await?;

        Ok(())
    }

    pub async fn get_latest_commitment(&self) -> Option<Digest> {
        self.syncer.get_latest_commitment().await
    }
}
