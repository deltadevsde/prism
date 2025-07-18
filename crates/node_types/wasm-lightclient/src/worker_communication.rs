use js_sys::Math;
use serde_wasm_bindgen::{from_value, to_value};
use tokio::sync::{Mutex, mpsc};
use wasm_bindgen::{closure::Closure, prelude::*};
use web_sys::{MessageEvent, console};

use crate::{
    commands::{LightClientCommand, WorkerResponse},
    worker::MessagePortLike,
};

pub fn random_id() -> u32 {
    (Math::random() * f64::from(u32::MAX)) as u32
}

// WorkerClient: Sends commands and receives responses in the main thread
// WorkerServer: Receives commands and sends responses in the worker thread

pub struct WorkerClient {
    port: MessagePortLike,
    response_channel: Mutex<mpsc::UnboundedReceiver<Result<WorkerResponse, JsError>>>,
    #[allow(dead_code)]
    // This field is kept to maintain the Closure and prevent the message handler from being
    // dropped.
    onmessage: Closure<dyn Fn(MessageEvent)>,
}

impl WorkerClient {
    pub fn new(port: MessagePortLike) -> Result<Self, JsError> {
        let (response_tx, response_rx) = mpsc::unbounded_channel();

        let onmessage: Closure<dyn Fn(MessageEvent)> =
            Closure::new(move |message_event: MessageEvent| {
                if let Ok(response) = from_value(message_event.data()) {
                    if response_tx.send(Ok(response)).is_err() {
                        console::error_1(&"Failed to forward response".into());
                    }
                }
            });

        port.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        Ok(WorkerClient {
            port,
            response_channel: Mutex::new(response_rx),
            onmessage,
        })
    }

    pub async fn exec(&self, command: LightClientCommand) -> Result<WorkerResponse, JsError> {
        let value = to_value(&command)?;
        self.port
            .post_message(&value)
            .map_err(|e| JsError::new(&format!("Failed to post message: {:?}", e)))?;

        let mut response_channel = self.response_channel.lock().await;
        response_channel
            .recv()
            .await
            .ok_or_else(|| JsError::new("response channel should never drop"))?
    }
}

pub struct WorkerServer {
    port: MessagePortLike,
    command_rx: mpsc::UnboundedReceiver<LightClientCommand>,
    #[allow(dead_code)]
    // This field is kept to maintain the Closure and prevent the message handler from being
    // dropped.
    onmessage: Closure<dyn Fn(MessageEvent)>,
}

impl WorkerServer {
    pub fn new(port: MessagePortLike) -> Result<Self, JsError> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let onmessage: Closure<dyn Fn(MessageEvent)> =
            Closure::new(move |message_event: MessageEvent| {
                if let Ok(command) = from_value(message_event.data()) {
                    if let Err(e) = command_tx.send(command) {
                        console::error_1(&format!("Failed to process command: {}", e).into());
                    }
                }
            });

        port.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        console::log_1(&"✅ WorkerServer initialized".into());
        Ok(WorkerServer {
            port,
            command_rx,
            onmessage,
        })
    }

    pub async fn recv(&mut self) -> Result<LightClientCommand, JsError> {
        self.command_rx.recv().await.ok_or_else(|| JsError::new("Channel closed"))
    }

    pub fn respond(&self, response: WorkerResponse) -> Result<(), JsError> {
        let value = to_value(&response).map_err(|e| JsError::new(&e.to_string()))?;
        self.port
            .post_message(&value)
            .map_err(|e| JsError::new(&format!("Failed to serialize response: {:?}", e)))
    }
}
