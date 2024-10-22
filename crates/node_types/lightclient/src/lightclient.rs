use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use ed25519_consensus::VerificationKey as VerifyingKey;
use prism_common::tree::Digest;
use prism_da::celestia::CelestiaConfig;

#[cfg(feature = "native")]
use anyhow::Context;
#[cfg(feature = "native")]
use prism_da::DataAvailabilityLayer;
#[cfg(feature = "native")]
use prism_errors::{DataAvailabilityError, GeneralError};
#[cfg(feature = "native")]
use sp1_sdk::ProverClient;
#[cfg(feature = "native")]
use sp1_sdk::SP1VerifyingKey;
#[cfg(feature = "native")]
use std::{self, sync::Arc};
#[cfg(feature = "native")]
use tokio::{sync::broadcast, task::spawn};

#[cfg(feature = "wasm")]
use crate::wasm::WasmDataAvailabilityLayer;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(feature = "wasm")]
use web_sys::console;

pub const PRISM_ELF: &[u8] = include_bytes!("../../../../elf/riscv32im-succinct-zkvm-elf");

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct LightClient {
    da: WasmDataAvailabilityLayer,
    prover_pubkey: Option<Vec<u8>>,
    // we dont need to store the prover client because we'll use the snark-bn254-verifier from where we can import a ProvingSystem, which should be wasm compatible
    verifying_key: Vec<u8>,
    pub start_height: u64,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl LightClient {
    #[wasm_bindgen(constructor)]
    pub fn new(da_config: JsValue, prover_pubkey: Option<String>) -> Result<LightClient, JsValue> {
        console_error_panic_hook::set_once();

        let cfg: CelestiaConfig = serde_wasm_bindgen::from_value(da_config)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse config: {}", e)))?;

        let da = WasmDataAvailabilityLayer::new(
            cfg.connection_string,
            cfg.start_height,
            cfg.snark_namespace_id,
            cfg.operation_namespace_id,
        );

        let prover_pubkey = prover_pubkey
            .map(|pk| {
                general_purpose::STANDARD
                    .decode(pk)
                    .map_err(|e| JsValue::from_str(&format!("Failed to decode public key: {}", e)))
            })
            .transpose()?;

        Ok(LightClient {
            da,
            verifying_key: Vec::new(), // only for the moment
            prover_pubkey,
            start_height: cfg.start_height,
        })
    }

    pub fn run(&self) -> js_sys::Promise {
        let future = async move {
            // TODO: start method
            if let Err(e) = self.da.start().await {
                return Err(JsValue::from_str(&format!(
                    "Failed to start DataAvailabilityLayer: {}",
                    e
                )));
            }

            if let Err(e) = self.sync_loop().await {
                return Err(JsValue::from_str(&format!(
                    "Sync loop failed: {}",
                    e.as_string().unwrap()
                )));
            }

            Ok(JsValue::undefined())
        };

        wasm_bindgen_futures::future_to_promise(future)
    }

    async fn sync_loop(&self) -> Result<(), JsValue> {
        console::log_1(&"Starting SNARK sync loop".into());
        let mut current_position = self.start_height;

        loop {
            let target = self.da.get_latest_height().await.map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to get latest height: {}",
                    e.as_string().unwrap()
                ))
            })?;

            for i in current_position..target {
                if let Err(e) = self.process_height(i).await {
                    console::error_1(&format!("Error processing height {}: {:?}", i, e).into());
                }
            }
            current_position = target;

            // In WASM, i don't that we have a good subscription mechanism, so lets use a timeout for now
            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
                web_sys::window()
                    .unwrap()
                    .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 5000)
                    .unwrap();
            }))
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to set timeout: {:?}", e)))?;
        }
    }

    async fn process_height(&self, height: u64) -> Result<(), JsValue> {
        match self.da.get_finalized_epoch(height + 1).await {
            Ok(wasm_epoch) => {
                match wasm_epoch.to_option()? {
                    Some(finalized_epoch) => {
                        console::log_1(
                            &format!("Light client: got epochs at height {}", height + 1).into(),
                        );

                        // Signature verification
                        if let Some(pubkey) = &self.prover_pubkey {
                            let verifying_key =
                                VerifyingKey::try_from(pubkey.as_slice()).map_err(|e| {
                                    JsValue::from_str(&format!("Invalid public key: {:?}", e))
                                })?;

                            finalized_epoch
                                .verify_signature(verifying_key)
                                .map_err(|e| {
                                    JsValue::from_str(&format!(
                                        "Invalid signature in epoch {}: {:?}",
                                        height, e
                                    ))
                                })?;
                        }

                        // Commitment verification
                        let prev_commitment = &finalized_epoch.prev_commitment;
                        let current_commitment = &finalized_epoch.current_commitment;
                        let mut public_values = finalized_epoch.proof.public_values.clone();
                        let proof_prev_commitment: Digest = public_values.read();
                        let proof_current_commitment: Digest = public_values.read();

                        if prev_commitment != &proof_prev_commitment
                            || current_commitment != &proof_current_commitment
                        {
                            return Err(JsValue::from_str(&format!(
                                "Commitment mismatch in epoch {}",
                                finalized_epoch.height
                            )));
                        }

                        console::log_1(&"SNARK verification not implemented for WASM".into());

                        console::log_1(
                            &format!("zkSNARK for epoch {} was processed", finalized_epoch.height)
                                .into(),
                        );
                    }
                    None => {
                        console::log_1(
                            &format!("No finalized epoch found at height: {}", height + 1).into(),
                        );
                    }
                }
            }
            Err(e) => {
                console::warn_1(
                    &format!("Light client: getting epoch: {}", e.as_string().unwrap()).into(),
                );
            }
        };
        Ok(())
    }
}

#[cfg(feature = "native")]
pub struct LightClient {
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub prover_pubkey: Option<VerifyingKey>,
    pub client: ProverClient,
    pub verifying_key: SP1VerifyingKey,
    pub start_height: u64,
}

#[cfg(feature = "native")]
impl LightClient {
    pub fn new(
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: CelestiaConfig,
        prover_pubkey: Option<VerifyingKey>,
    ) -> LightClient {
        #[cfg(feature = "mock_prover")]
        let client = ProverClient::mock();
        #[cfg(not(feature = "mock_prover"))]
        let client = ProverClient::local();
        let (_, verifying_key) = client.setup(PRISM_ELF);

        LightClient {
            da,
            verifying_key,
            client,
            prover_pubkey,
            start_height: cfg.start_height,
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        // start listening for new headers to update sync target
        self.da
            .start()
            .await
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))
            .context("Failed to start DataAvailabilityLayer")?;

        self.sync_loop()
            .await
            .map_err(|e| GeneralError::InitializationError(e.to_string()))
            .context("Sync loop failed")
    }

    async fn sync_loop(self: Arc<Self>) -> Result<(), tokio::task::JoinError> {
        info!("starting SNARK sync loop");
        let start_height = self.start_height;
        spawn(async move {
            let mut current_position = start_height;
            let mut height_rx = self.da.subscribe_to_heights();

            loop {
                match height_rx.recv().await {
                    Ok(target) => {
                        for i in current_position..target {
                            if let Err(e) = self.process_height(i).await {
                                error!("Error processing height {}: {:?}", i, e);
                            }
                        }
                        current_position = target;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        error!("Height channel closed unexpectedly");
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!("Lagged behind by {} messages", skipped);
                    }
                }
            }
        })
        .await
    }

    // maybe we can use the same function for wasm and native when we're switching back to cfg target arch, but idk if theres a good way with slightly different structs
    async fn process_height(&self, height: u64) -> Result<(), anyhow::Error> {
        match self.da.get_finalized_epoch(height + 1).await {
            Ok(Some(finalized_epoch)) => {
                debug!("light client: got epochs at height {}", height + 1);

                // Signature verification
                if let Some(pubkey) = &self.prover_pubkey {
                    finalized_epoch.verify_signature(*pubkey).map_err(|e| {
                        anyhow::anyhow!("Invalid signature in epoch {}: {:?}", height, e)
                    })?;
                }

                // Commitment verification
                let prev_commitment = &finalized_epoch.prev_commitment;
                let current_commitment = &finalized_epoch.current_commitment;
                let mut public_values = finalized_epoch.proof.public_values.clone();
                let proof_prev_commitment: Digest = public_values.read();
                let proof_current_commitment: Digest = public_values.read();

                if prev_commitment != &proof_prev_commitment
                    || current_commitment != &proof_current_commitment
                {
                    return Err(anyhow::anyhow!(
                        "Commitment mismatch in epoch {}",
                        finalized_epoch.height
                    ));
                }

                // SNARK verification
                self.client
                    .verify(&finalized_epoch.proof, &self.verifying_key)
                    .map_err(|err| {
                        anyhow::anyhow!(
                            "Failed to validate epoch at height {}: {:?}",
                            finalized_epoch.height,
                            err
                        )
                    })?;

                info!(
                    "zkSNARK for epoch {} was validated successfully",
                    finalized_epoch.height
                );
            }
            Ok(None) => {
                debug!("no finalized epoch found at height: {}", height + 1);
            }
            Err(e) => {
                debug!("light client: getting epoch: {}", e);
            }
        };
        Ok(())
    }
}
