use web_sys::{console, MessagePort};

use crate::{
    celestia::{CelestiaConfig, WasmCelestiaClient},
    commands::{LightClientCommand, WorkerResponse},
    worker_communication::WorkerServer,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct LightClientWorker {
    server: WorkerServer,
    celestia: WasmCelestiaClient,
}

#[wasm_bindgen]
impl LightClientWorker {
    #[wasm_bindgen(constructor)]
    pub async fn new(port: MessagePort) -> Result<LightClientWorker, JsError> {
        console::log_1(&"• Initializing LightClientWorker  ✔".into());
        let mut server = WorkerServer::new();
        server.initialize(port)?;

        let celestia = WasmCelestiaClient::new(CelestiaConfig::default()).await?;

        console::log_1(&"• Server registered  ✔".into());

        Ok(Self { server, celestia })
    }

    pub async fn run(&mut self) -> Result<(), JsError> {
        console::log_1(&"• Starting LightClientWorker ✔".into());
        while let Ok(command) = self.server.recv().await {
            let response = match command {
                LightClientCommand::VerifyEpoch { height } => {
                    console::log_2(&"• Verifying epoch....".into(), &height.into());
                    match self.celestia.verify_epoch(height).await {
                        Ok(true) => WorkerResponse::EpochVerified,
                        Ok(false) => WorkerResponse::Error("No epoch data found".to_string()),
                        Err(e) => {
                            WorkerResponse::Error(format!("Failed to verify epoch...{:?}", e,))
                        }
                    }
                }
                LightClientCommand::GetCurrentHeight => {
                    WorkerResponse::CurrentHeight(self.celestia.get_current_height().await)
                }
                LightClientCommand::SetProverKey(_) => WorkerResponse::ProverKeySet, // TODO if needed
            };

            self.server.respond(response);
        }
        Ok(())
    }
}
