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
            match from_value(message_event.data()) {
                Ok(response) => {
                    if let Err(e) = response_tx.send(Ok(response)) {
                        console::error_1(&format!("Failed to forward response: {}", e).into());
                    }
                }
                Err(e) => {
                    console::error_1(&format!("Failed to deserialize response: {}", e).into());
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
        let mut response_channel = self.response_channel.lock().await;
        console::log_2(&"🩺 executing".into(), &to_value(&command)?);

        self.port
            .post_message(&to_value(&command)?)
            .map_err(|e| JsError::new(&format!("Failed to post message: {:?}", e)))?;

        console::log_1(&"📨 message posted".into());

        // maybe we should loop and filter out some messages...
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
            match from_value(message_event.data()) {
                Ok(command) => {
                    if let Err(e) = command_tx.send(command) {
                        console::error_1(&format!("Failed to process command: {}", e).into());
                    }
                }
                Err(e) => {
                    console::error_1(&format!("Failed to deserialize command: {}", e).into());
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
        self.command_rx
            .recv()
            .await
            .ok_or_else(|| JsError::new("Channel closed"))
    }

    pub fn respond(&self, response: WorkerResponse) {
        match to_value(&response) {
            Ok(response_value) => {
                if let Err(e) = self.port.post_message(&response_value) {
                    console::error_1(&format!("Failed to send response: {:?}", e).into());
                }
            }
            Err(e) => {
                console::error_1(&format!("Failed to serialize response: {:?}", e).into());
            }
        }
    }
}
