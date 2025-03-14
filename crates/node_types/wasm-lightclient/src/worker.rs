use js_sys::Function;
use prism_da::celestia::{light_client::LightClientConnection, utils::Network};
use prism_lightclient::{
    events::{EventChannel, EventPublisher, EventSubscriber, LightClientEvent},
    LightClient,
};
use std::{str::FromStr, sync::Arc};
use wasm_bindgen_futures::spawn_local;
use web_sys::{console, BroadcastChannel, MessagePort};

use crate::{
    commands::{LightClientCommand, WorkerResponse},
    worker_communication::{random_id, WorkerServer},
};
use wasm_bindgen::{prelude::*, JsCast};

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

        let (
            events_channel_name,
            light_client_event_publisher,
            light_client_event_subscriber,
            js_channel,
        ) = initialize_event_channel()?;

        // forward the internal light client events to the main thread
        spawn_local(forward_events(
            light_client_event_subscriber,
            js_channel.clone(),
        ));

        // Initialize network and DA layer
        let network = Network::from_str(network)
            .map_err(|e| JsError::new(&format!("Invalid network: {}", e)))?;
        let network_config = network.config();

        let da = Arc::new(
            LightClientConnection::new(&network_config)
                .await
                .map_err(|e| JsError::new(&format!("Failed to connect to light client: {}", e)))?,
        );

        let start_height = network_config
            .celestia_config
            .as_ref()
            .map(|cfg| cfg.start_height)
            .expect("Start height not set");

        let verifying_key = network_config.verifying_key;

        let light_client = Arc::new(LightClient::new(
            da,
            start_height,
            verifying_key,
            light_client_event_publisher,
        ));

        Ok(Self {
            server,
            light_client,
            events_channel_name: events_channel_name.to_string(),
        })
    }

    pub async fn run(&mut self) -> Result<(), JsError> {
        let light_client = Arc::clone(&self.light_client);
        light_client
            .run()
            .await
            .map_err(|e| JsError::new(&format!("Light client error: {}", e)))?;

        while let Ok(command) = self.server.recv().await {
            let response = match command {
                LightClientCommand::GetCurrentCommitment => {
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
}

fn initialize_event_channel(
) -> Result<(String, EventPublisher, EventSubscriber, BroadcastChannel), JsError> {
    let events_channel_name = format!("lightclient-events-{}", random_id());
    let light_client_event_channel = EventChannel::new();
    let event_publisher = light_client_event_channel.publisher();
    let event_subscriber = light_client_event_channel.subscribe();
    let js_channel = BroadcastChannel::new(events_channel_name.as_str())
        .map_err(|e| JsError::new(&format!("Failed to create broadcast channel: {:?}", e)))?;
    Ok((
        events_channel_name,
        event_publisher,
        event_subscriber,
        js_channel,
    ))
}

async fn forward_events(mut subscriber: EventSubscriber, channel: BroadcastChannel) {
    while let Ok(event) = subscriber.recv().await {
        if let Ok(event_json) = serde_wasm_bindgen::to_value(&event) {
            match &event.event {
                LightClientEvent::LuminaEvent { .. } => {} // Do nothing for Lumina events
                _ => console::log_2(&"📨 Forwarding event".into(), &event_json),
            }
            if let Err(e) = channel.post_message(&event_json) {
                console::error_1(&format!("Failed to post message: {:?}", e).into());
            }
        }
    }
}
