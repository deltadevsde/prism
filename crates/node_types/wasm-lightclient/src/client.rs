use wasm_bindgen::prelude::*;
use web_sys::MessagePort;

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
        Ok(Self {
            worker: WorkerClient::new(port)?,
        })
    }

    #[wasm_bindgen(js_name = verifyEpoch)]
    pub async fn verify_epoch(&self, height: u64) -> Result<(), JsError> {
        match self
            .worker
            .exec(LightClientCommand::VerifyEpoch { height })
            .await?
        {
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
