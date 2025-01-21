use std::sync::Arc;
use web_sys::{console, MessagePort};

use crate::{
    celestia::client::WasmCelestiaClient,
    commands::{LightClientCommand, WorkerResponse},
    worker_communication::WorkerServer,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct LightClientWorker {
    server: WorkerServer,
    celestia: Arc<WasmCelestiaClient>,
}

#[wasm_bindgen]
impl LightClientWorker {
    #[wasm_bindgen(constructor)]
    pub async fn new(port: MessagePort) -> Result<LightClientWorker, JsError> {
        Ok(Self {
            server: WorkerServer::new(port.clone())?,
            celestia: WasmCelestiaClient::new(port).await?,
        })
    }

    pub async fn run(&mut self) -> Result<(), JsError> {
        console::log_1(&"• Starting LightClientWorker ✔".into());
        while let Ok(command) = self.server.recv().await {
            let response = match command {
                LightClientCommand::VerifyEpoch { height } => {
                    match self.celestia.verify_epoch(height).await {
                        Ok(value) => WorkerResponse::EpochVerified {
                            verified: value,
                            height,
                        },
                        Err(e) => {
                            WorkerResponse::Error(format!("Failed to verify epoch...{:?}", e,))
                        }
                    }
                }
                LightClientCommand::GetCurrentHeight => {
                    WorkerResponse::CurrentHeight(self.celestia.get_current_height().await)
                }
                LightClientCommand::GetAccount(account_id) => WorkerResponse::GetAccount(None), // TODO: implement this
            };

            self.server.respond(response);
        }
        Ok(())
    }
}
