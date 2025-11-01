use js_sys::Function;
use prism_events::{EventSubscriber, PrismEvent};
use prism_lightclient::{LightClient, LightClientConfig, create_light_client};
use prism_presets::{ApplyPreset, LightClientPreset};
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
    pub async fn new(port_value: JsValue, preset_str: &str) -> Result<LightClientWorker, JsError> {
        let port: MessagePortLike = port_value.unchecked_into::<MessagePortLike>();

        let server = WorkerServer::new(port)?;

        // Initialize network and DA layer
        let preset =
            LightClientPreset::from_str(preset_str).map_err(|e| JsError::new(&e.to_string()))?;

        let config = LightClientConfig::default_with_preset(&preset)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let light_client = create_light_client(&config)
            .await
            .map_err(|e| JsError::new(&format!("Failed to create light client: {}", e)))?;

        let events_channel_name = format!("lightclient-events-{}", random_id());

        Ok(Self {
            server,
            light_client: Arc::new(light_client),
            events_channel_name: events_channel_name.to_string(),
        })
    }

    pub async fn run(&mut self) -> Result<(), JsError> {
        console::log_1(&"🌟 Starting Light Client Worker".into());

        let event_sub = self
            .light_client
            .start_subscribed()
            .await
            .map_err(|e| JsError::new(&format!("Starting light client failed: {}", e)))?;

        let js_channel = BroadcastChannel::new(&self.events_channel_name)
            .map_err(|e| JsError::new(&format!("Failed to create broadcast channel: {:?}", e)))?;

        // forward the internal light client events to the main thread
        spawn_local(forward_events(event_sub, js_channel.clone()));

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
    pub async fn new_with_custom_light_client(
        port_value: JsValue,
        light_client: LightClient,
    ) -> Result<LightClientWorker, JsError> {
        let port: MessagePortLike = port_value.unchecked_into::<MessagePortLike>();
        let server = WorkerServer::new(port)?;

        let events_channel_name = format!("lightclient-events-{}", random_id());

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
                _ => console::log_2(
                    &"📨 Forwarding event".into(),
                    &format!("{:?}", event).into(),
                ),
            }
            if let Err(e) = channel.post_message(&event_json) {
                console::error_1(&format!("Failed to post message: {:?}", e).into());
            }
        }
    }
}
