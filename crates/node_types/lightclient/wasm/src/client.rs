use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;
use web_sys::{console, MessagePort};

use crate::{
    commands::{LightClientCommand, WorkerResponse},
    worker_communication::WorkerClient,
};

// lives in main thread, communicates with worker
#[wasm_bindgen]
pub struct WasmLightClient {
    worker: WorkerClient,
}

#[wasm_bindgen]
impl WasmLightClient {
    #[wasm_bindgen(constructor)]
    pub async fn new(port: MessagePort) -> Result<WasmLightClient, JsError> {
        let worker = WorkerClient::new(port)?;

        let response = worker.exec(LightClientCommand::InternalPing).await?; // ping to ensure connection?
        console::log_2(
            &"• Connected to worker ✔ Command:".into(),
            &to_value(&response).map_err(|e| JsError::new(&e.to_string()))?,
        );
        if !matches!(response, WorkerResponse::InternalPong) {
            return Err(JsError::new("Failed to connect to worker"));
        }

        Ok(Self { worker })
    }

    #[wasm_bindgen(js_name = verifyEpoch)]
    pub async fn verify_epoch(&self, height: u64) -> Result<(), JsError> {
        let command = LightClientCommand::VerifyEpoch { height };
        match self.worker.exec(command).await? {
            WorkerResponse::EpochVerified => Ok(()),
            WorkerResponse::Error(e) => Err(JsError::new(&e)),
            _ => Err(JsError::new("Unexpected response")),
        }
    }

    #[wasm_bindgen(js_name = getCurrentHeight)]
    pub async fn get_current_height(&self) -> Result<u64, JsError> {
        match self
            .worker
            .exec(LightClientCommand::GetCurrentHeight)
            .await?
        {
            WorkerResponse::CurrentHeight(height) => Ok(height),
            WorkerResponse::Error(e) => Err(JsError::new(&e)),
            _ => Err(JsError::new("Unexpected response")),
        }
    }
}
