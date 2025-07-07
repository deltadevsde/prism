use js_sys::Function;
use prism_da::{
    celestia::{light_client::LightClientConnection, utils::Network},
    events::{EventSubscriber, PrismEvent},
};
use prism_lightclient::LightClient;
use std::{str::FromStr, sync::Arc};
use wasm_bindgen_futures::spawn_local;
use web_sys::{BroadcastChannel, MessagePort, console};

use crate::{
    commands::{LightClientCommand, WorkerResponse},
    worker_communication::{WorkerServer, random_id},
};
use wasm_bindgen::{JsCast, prelude::*};

#[wasm_bindgen]
pub struct LightClientWorker {
    server: WorkerServer,
    light_client: Arc<LightClient>,
    events_channel_name: String,
}

#[wasm_bindgen]
extern "C" {
    pub type MessagePortLike;

    #[wasm_bindgen(catch, method, structural, js_name = postMessage)]
    pub fn post_message(this: &MessagePortLike, message: &JsValue) -> Result<(), JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = postMessage)]
    pub fn post_message_with_transferable(
        this: &MessagePortLike,
        message: &JsValue,
        transferable: &JsValue,
    ) -> Result<(), JsValue>;

    #[wasm_bindgen(method, structural, setter, js_name = onmessage)]
    pub fn set_onmessage(this: &MessagePortLike, handler: Option<&Function>);
}

impl From<MessagePort> for MessagePortLike {
    fn from(port: MessagePort) -> Self {
        JsValue::from(port).into()
    }
}

#[wasm_bindgen]
impl LightClientWorker {
    #[wasm_bindgen(constructor)]
    pub async fn new(port_value: JsValue, network: &str) -> Result<LightClientWorker, JsError> {
        let port: MessagePortLike = port_value.unchecked_into::<MessagePortLike>();

        let server = WorkerServer::new(port)?;

        let events_channel_name = format!("lightclient-events-{}", random_id());
        let js_channel = BroadcastChannel::new(&events_channel_name)
            .map_err(|e| JsError::new(&format!("Failed to create broadcast channel: {:?}", e)))?;

        // Initialize network and DA layer
        let network = Network::from_str(network)
            .map_err(|e| JsError::new(&format!("Invalid network: {}", e)))?;
        let network_config = network.config();

        let da = Arc::new(
            LightClientConnection::new(&network_config)
                .await
                .map_err(|e| JsError::new(&format!("Failed to connect to light client: {}", e)))?,
        );

        // forward the internal light client events to the main thread
        spawn_local(forward_events(
            da.event_channel.subscribe(),
            js_channel.clone(),
        ));

        let verifying_key = network_config.verifying_key;

        let light_client = Arc::new(LightClient::new(da, verifying_key));

        Ok(Self {
            server,
            light_client,
            events_channel_name: events_channel_name.to_string(),
        })
    }

    pub async fn run(&mut self) -> Result<(), JsError> {
        console::log_1(&"🌟 Starting Light Client Worker".into());
        let light_client = Arc::clone(&self.light_client);
        spawn_local(async move {
            console::log_1(&"🚀 Starting light client in background".into());
            if let Err(e) = light_client.run().await {
                console::error_1(&format!("Light client error: {}", e).into());
            }
        });

        console::log_1(&"🌟 Light Client Worker started".into());

        while let Ok(command) = self.server.recv().await {
            let response = match command {
                LightClientCommand::GetCurrentCommitment => {
                    console::log_1(&"📥 Received GetCurrentCommitment command".into());
                    match self.light_client.get_latest_commitment().await {
                        Some(commitment) => {
                            WorkerResponse::CurrentCommitment(commitment.to_string())
                        }
                        None => WorkerResponse::Error("No commitment available yet".to_string()),
                    }
                }
                LightClientCommand::GetEventsChannelName => {
                    WorkerResponse::EventsChannelName(self.events_channel_name.clone())
                }
            };

            self.server.respond(response)?;
        }

        Ok(())
    }

    #[wasm_bindgen(getter)]
    pub fn events_channel_name(&self) -> String {
        self.events_channel_name.clone()
    }
}

#[cfg(test)]
impl LightClientWorker {
    pub async fn new_with_da(
        port_value: JsValue,
        da: Arc<dyn prism_da::LightDataAvailabilityLayer>,
    ) -> Result<LightClientWorker, JsError> {
        let port: MessagePortLike = port_value.unchecked_into::<MessagePortLike>();
        let server = WorkerServer::new(port)?;

        let events_channel_name = format!("lightclient-events-{}", random_id());
        let js_channel = BroadcastChannel::new(&events_channel_name)
            .map_err(|e| JsError::new(&format!("Failed to create broadcast channel: {:?}", e)))?;

        // forward the internal light client events to the main thread here as well
        spawn_local(forward_events(
            da.event_channel().subscribe(),
            js_channel.clone(),
        ));

        let network = Network::from_str("specter")
            .map_err(|e| JsError::new(&format!("Invalid network: {}", e)))?;
        let verifying_key = network.config().verifying_key;

        let light_client = Arc::new(LightClient::new(da, verifying_key));

        Ok(Self {
            server,
            light_client,
            events_channel_name: events_channel_name.to_string(),
        })
    }
}

async fn forward_events(mut subscriber: EventSubscriber, channel: BroadcastChannel) {
    while let Ok(event) = subscriber.recv().await {
        if let Ok(event_json) = serde_wasm_bindgen::to_value(&event) {
            match &event.event {
                PrismEvent::LuminaEvent { .. } => {} // Do nothing for Lumina events
                _ => console::log_2(&"📨 Forwarding event".into(), &event_json),
            }
            if let Err(e) = channel.post_message(&event_json) {
                console::error_1(&format!("Failed to post message: {:?}", e).into());
            }
        }
    }
}
