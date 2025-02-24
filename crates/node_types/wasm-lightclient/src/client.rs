use wasm_bindgen::prelude::*;
use web_sys::BroadcastChannel;

use crate::{
    commands::{LightClientCommand, WorkerResponse},
    worker::MessagePortLike,
    worker_communication::WorkerClient,
};

#[wasm_bindgen]
pub struct VerifyEpochResult {
    pub verified: bool,
    pub height: u64,
}

#[wasm_bindgen]
impl VerifyEpochResult {
    pub fn new(verified: bool, height: u64) -> Self {
        Self { verified, height }
    }
}

// lives in main thread, communicates with worker
#[wasm_bindgen]
pub struct WasmLightClient {
    worker_client: WorkerClient,
}

#[wasm_bindgen]
impl WasmLightClient {
    #[wasm_bindgen(constructor)]
    pub async fn new(worker_js: JsValue) -> Result<WasmLightClient, JsError> {
        let worker_client = WorkerClient::new(worker_js.unchecked_into::<MessagePortLike>())?;

        Ok(Self { worker_client })
    }

    #[wasm_bindgen(js_name = getCurrentCommitment)]
    pub async fn get_current_commitment(&self) -> Result<String, JsError> {
        match self.worker_client.exec(LightClientCommand::GetCurrentCommitment).await? {
            WorkerResponse::CurrentCommitment(commitment) => Ok(commitment),
            WorkerResponse::Error(e) => Err(JsError::new(&e)),
            _ => Err(JsError::new("Unexpected response")),
        }
    }

    #[wasm_bindgen(js_name = "eventsChannel")]
    pub async fn events_channel(&self) -> Result<BroadcastChannel, JsError> {
        match self.worker_client.exec(LightClientCommand::GetEventsChannelName).await? {
            WorkerResponse::EventsChannelName(name) => BroadcastChannel::new(&name)
                .map_err(|_| JsError::new("Failed to create events channel")),
            WorkerResponse::Error(e) => Err(JsError::new(&e)),
            _ => Err(JsError::new("Unexpected response type")),
        }
    }
}
