use serde_wasm_bindgen::{from_value, to_value};
use tokio::sync::{mpsc, Mutex};
use wasm_bindgen::{closure::Closure, prelude::*};
use web_sys::{console, MessageEvent, MessagePort};

use crate::commands::{LightClientCommand, WorkerResponse};

// WorkerClient: Sends commands and receives responses in the main thread
// WorkerServer: Receives commands and sends responses in the worker thread

pub struct WorkerClient {
    port: MessagePort,
    response_channel: Mutex<mpsc::UnboundedReceiver<Result<WorkerResponse, JsError>>>,
    onmessage: Closure<dyn Fn(MessageEvent)>,
}

impl WorkerClient {
    pub fn new(port: MessagePort) -> Result<Self, JsError> {
        let (response_tx, response_rx) = mpsc::unbounded_channel();

        let onmessage = Closure::new(move |message_event: MessageEvent| {
            if let Ok(response) = from_value(message_event.data()) {
                if response_tx.send(Ok(response)).is_err() {
                    console::error_1(&format!("Failed to forward response").into());
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
            .ok_or_else(|| JsError::new("response channel shoulld  never drop"))?
    }
}

// Doesn't need Mutex because it's designed to process one command at a time sequentially
pub struct WorkerServer {
    port: MessagePort,
    command_rx: mpsc::UnboundedReceiver<LightClientCommand>,
    onmessage: Closure<dyn Fn(MessageEvent)>,
}

impl WorkerServer {
    pub fn new(port: MessagePort) -> Result<Self, JsError> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let onmessage = Closure::new(move |message_event: MessageEvent| {
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
