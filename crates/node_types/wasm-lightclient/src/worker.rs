use js_sys::Function;
use prism_da::create_light_client_da_layer;
use prism_events::{EventSubscriber, PrismEvent};
use prism_lightclient::{LightClient, create_light_client};
use prism_presets::{ApplyPreset, LightClientPreset};
use std::{str::FromStr, sync::Arc};
use tokio_util::sync::CancellationToken;
use wasm_bindgen_futures::spawn_local;
use web_sys::{BroadcastChannel, MessagePort, console};

use crate::{
    commands::{LightClientCommand, WorkerResponse},
    config::WasmLightClientConfig,
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
    pub async fn new(port_value: JsValue, preset_str: &str) -> Result<LightClientWorker, JsError> {
        let port: MessagePortLike = port_value.unchecked_into::<MessagePortLike>();

        let server = WorkerServer::new(port)?;

        let events_channel_name = format!("lightclient-events-{}", random_id());
        let js_channel = BroadcastChannel::new(&events_channel_name)
            .map_err(|e| JsError::new(&format!("Failed to create broadcast channel: {:?}", e)))?;

        // Initialize network and DA layer
        let preset =
            LightClientPreset::from_str(preset_str).map_err(|e| JsError::new(&e.to_string()))?;

        let config = WasmLightClientConfig::default_with_preset(&preset)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let da = create_light_client_da_layer(&config.da)
            .await
            .map_err(|e| JsError::new(&format!("Failed to connect to light client: {}", e)))?;

        // forward the internal light client events to the main thread
        spawn_local(forward_events(
            da.event_channel().subscribe(),
            js_channel.clone(),
        ));

        let ct = CancellationToken::new();

        let light_client = create_light_client(da, &config.light_client, ct.clone())
            .map_err(|e| JsError::new(&format!("Failed to create light client: {}", e)))?;

        Ok(Self {
            server,
            light_client: Arc::new(light_client),
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

        let preset = LightClientPreset::Specter;

        let config = WasmLightClientConfig::default_with_preset(&preset)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let ct = CancellationToken::new();
        let light_client = create_light_client(da, &config.light_client, ct)
            .map_err(|e| JsError::new(&format!("Failed to create light client: {}", e)))?;

        Ok(Self {
            server,
            light_client: Arc::new(light_client),
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
