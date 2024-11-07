use serde_wasm_bindgen::{from_value, to_value};
use tokio::sync::{mpsc, Mutex};
use wasm_bindgen::{closure::Closure, prelude::*};
use web_sys::{console, MessageEvent, MessagePort};

use crate::commands::{LightClientCommand, WorkerResponse};

struct ClientConnection {
    port: MessagePort,
    onmessage: Closure<dyn Fn(MessageEvent)>,
}

impl ClientConnection {
    fn new(
        port: MessagePort,
        server_tx: mpsc::UnboundedSender<LightClientCommand>,
    ) -> Result<Self, JsError> {
        // We need the Closure because it's how we handle incoming messages from the MessagePort. It's basically our event handler.
        let onmessage = Closure::new(move |message_event: MessageEvent| {
            match from_value(message_event.data()) {
                Ok(command) => {
                    if let Err(e) = server_tx.send(command) {
                        web_sys::console::error_1(&format!("Failed to send command: {}", e).into());
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(
                        &format!("Failed to deserialize message: {}", e).into(),
                    );
                }
            }
        });

        port.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        Ok(ClientConnection { port, onmessage })
    }

    fn send(&self, message: &WorkerResponse) -> Result<(), JsError> {
        let message_value = to_value(message)?;
        self.port
            .post_message(&message_value)
            .map_err(|e| JsError::new(&format!("Failed to post message: {:?}", e)))?;
        Ok(())
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.port.set_onmessage(None);
    }
}

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
                response_tx.send(Ok(response));
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
        let command_value = to_value(&command)?;

        self.port
            .post_message(&command_value)
            .map_err(|e| JsError::new(&format!("Failed to post message: {:?}", e)))?;

        console::log_1(&"📨 message posted".into());

        // maybe we should loop and filter out some messages...
        response_channel
            .recv()
            .await
            .ok_or_else(|| JsError::new("response channel shoulld  never drop"))?
    }
}

impl Drop for WorkerClient {
    fn drop(&mut self) {
        self.port.set_onmessage(None);
    }
}

// Doesn't need Mutex because it's designed to process one command at a time sequentially
pub struct WorkerServer {
    connection: Option<ClientConnection>,
    client_tx: mpsc::UnboundedSender<LightClientCommand>,
    client_rx: mpsc::UnboundedReceiver<LightClientCommand>,
}

impl Default for WorkerServer {
    fn default() -> Self {
        let (client_tx, client_rx) = mpsc::unbounded_channel();

        WorkerServer {
            connection: None,
            client_tx,
            client_rx,
        }
    }
}

impl WorkerServer {
    pub fn new() -> Self {
        console::log_1(&"👷🏼‍♂️ WorkerServer created ✔️".into());

        Self::default()
    }

    pub fn initialize(&mut self, port: MessagePort) -> Result<(), JsError> {
        self.connection = Some(ClientConnection::new(port, self.client_tx.clone())?);
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<LightClientCommand, JsError> {
        self.client_rx
            .recv()
            .await
            .ok_or_else(|| JsError::new("Channel closed"))
    }

    pub fn respond(&self, response: WorkerResponse) {
        if let Some(connection) = &self.connection {
            if let Err(e) = connection.send(&response) {
                web_sys::console::error_1(&format!("Failed to send response: {:?}", &e).into());
            }
        }
    }
}
