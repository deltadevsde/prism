use prism_da::celestia::{light_client::LightClientConnection, utils::Network};
use prism_lightclient::LightClient;
use std::{str::FromStr, sync::Arc};
use web_sys::{console, MessagePort};

use crate::{
    commands::{LightClientCommand, WorkerResponse},
    worker_communication::WorkerServer,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct LightClientWorker {
    server: WorkerServer,
    light_client: Arc<LightClient>,
}

#[wasm_bindgen]
impl LightClientWorker {
    // todo: better config handling
    #[wasm_bindgen(constructor)]
    pub async fn new(port: MessagePort, network: &str) -> Result<LightClientWorker, JsError> {
        console::log_1(&"LightClientWorker starting...".into());

        // Initialize network and DA layer
        let network = Network::from_str(network)
            .map_err(|e| JsError::new(&format!("Invalid network: {}", e)))?;
        let network_config = network.config();

        let da = Arc::new(
            LightClientConnection::new(&network_config)
                .await
                .map_err(|e| JsError::new(&format!("Failed to connect to light client: {}", e)))?,
        );

        console::log_1(&"DA layer initialized".into());

        let start_height =
            network_config.celestia_config.as_ref().map(|cfg| cfg.start_height).unwrap_or(4279075);

        let verifying_key = network_config.verifying_key;
        let sp1_vkey = network_config
            .celestia_config
            .as_ref()
            .map(|cfg| cfg.snark_namespace_id.clone())
            .unwrap_or_else(|| "default_sp1_vkey".to_string());

        // Create the light client
        let light_client = Arc::new(LightClient::new(da, start_height, verifying_key, sp1_vkey));

        // Initialize the worker server for message handling
        let server = WorkerServer::new(port)?;

        console::log_1(&"LightClientWorker initialized".into());

        Ok(Self {
            server,
            light_client,
        })
    }

    pub async fn run(&mut self) -> Result<(), JsError> {
        let light_client = Arc::clone(&self.light_client);
        light_client
            .run()
            .await
            .map_err(|e| JsError::new(&format!("Light client error: {}", e)))?;

        while let Ok(command) = self.server.recv().await {
            // Todo: here we can add more / real commands
            let response = match command {
                LightClientCommand::VerifyEpoch { height } => {
                    match self.light_client.da.get_finalized_epoch(height).await {
                        Ok(Some(epoch)) => WorkerResponse::EpochVerified {
                            verified: true,
                            height,
                        },
                        Ok(None) => WorkerResponse::NoEpochFound { height },
                        Err(e) => WorkerResponse::Error(e.to_string()),
                    }
                }
                LightClientCommand::GetCurrentHeight => WorkerResponse::CurrentHeight(0),
                LightClientCommand::GetAccount(_) => WorkerResponse::GetAccount(None),
            };

            self.server.respond(response)?;
        }

        Ok(())
    }
}
