use anyhow::Result;
use lumina_node_uniffi::{LuminaNode, types::NodeConfig};
use prism_da::{LightDataAvailabilityLayer, celestia::utils::Network};
use prism_keys::VerifyingKey;
use prism_lightclient::{
    LightClient,
    events::{EventChannel, EventInfo, EventSubscriber, LightClientEvent},
};
use std::{
    sync::{Arc, Mutex},
    time::SystemTime,
};
use tokio::runtime::Runtime;

// Re-export the UniFFI generated scaffolding code
uniffi::setup_scaffolding!();

// Set up error handling for UniFFI
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LightClientError {
    #[error("Light client error: {message}")]
    General { message: String },

    #[error("Network error: {message}")]
    Network { message: String },

    #[error("Verification error: {message}")]
    Verification { message: String },

    #[error("DA layer error: {message}")]
    DALayer { message: String },
}

impl From<anyhow::Error> for LightClientError {
    fn from(error: anyhow::Error) -> Self {
        LightClientError::General {
            message: error.to_string(),
        }
    }
}

// Event type to expose via UniFFI
#[derive(Debug, Clone, uniffi::Record)]
pub struct UniffiLightClientEvent {
    pub event_type: String,
    pub height: Option<u64>,
    pub commitment: Option<String>,
    pub error: Option<String>,
    pub timestamp: u64,
    pub formatted_log: String,
}

impl From<EventInfo> for UniffiLightClientEvent {
    fn from(info: EventInfo) -> Self {
        let (event_type, height, commitment, error) = match &info.event {
            LightClientEvent::SyncStarted { height } => {
                ("sync_started".to_string(), Some(*height), None, None)
            }
            LightClientEvent::UpdateDAHeight { height } => {
                ("update_da_height".to_string(), Some(*height), None, None)
            }
            LightClientEvent::EpochVerificationStarted { height } => (
                "epoch_verification_started".to_string(),
                Some(*height),
                None,
                None,
            ),
            LightClientEvent::EpochVerified { height } => {
                ("epoch_verified".to_string(), Some(*height), None, None)
            }
            LightClientEvent::EpochVerificationFailed { height, error } => (
                "epoch_verification_failed".to_string(),
                Some(*height),
                None,
                Some(error.clone()),
            ),
            LightClientEvent::NoEpochFound { height } => {
                ("no_epoch_found".to_string(), Some(*height), None, None)
            }
            LightClientEvent::HeightChannelClosed => {
                ("height_channel_closed".to_string(), None, None, None)
            }
            LightClientEvent::GetCurrentCommitment { commitment } => (
                "get_current_commitment".to_string(),
                None,
                Some(commitment.to_string()),
                None,
            ),
            LightClientEvent::RecursiveVerificationStarted { height } => (
                "recursive_verification_started".to_string(),
                Some(*height),
                None,
                None,
            ),
            LightClientEvent::RecursiveVerificationCompleted { height } => (
                "recursive_verification_completed".to_string(),
                Some(*height),
                None,
                None,
            ),
            LightClientEvent::LuminaEvent { event } => {
                ("lumina_event".to_string(), None, None, None)
            }
        };

        let timestamp = match info.time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => 0,
        };

        UniffiLightClientEvent {
            event_type,
            height,
            commitment,
            error,
            timestamp,
            formatted_log: info.formatted_log,
        }
    }
}

// Helper struct for configuring the light client
#[derive(Debug, Clone, uniffi::Record)]
pub struct LightClientConfig {
    pub da_provider: String,
    pub start_height: u64,
    pub prover_pubkey: Option<VerifyingKey>,
}

// Main light client interface for UniFFI
#[derive(uniffi::Object)]
pub struct UniffiLightClient {
    light_client: Arc<LightClient>,
    runtime: Arc<Runtime>,
    events_subscriber: Mutex<Option<EventSubscriber>>,
}

impl UniffiLightClient {
    #[uniffi::constructor]
    pub async fn new(
        config: LightClientConfig,
        lumina_node_config: NodeConfig,
    ) -> Result<Self, LightClientError> {
        let runtime = Arc::new(Runtime::new().unwrap());

        // Initialize the appropriate DA layer based on provider string
        let da = runtime.block_on(async {
            match config.da_provider.as_str() {
                s if s.starts_with("celestia:") => {
                    let config = Network::config(&Network::Specter);
                    let node = LuminaNode::new(lumina_node_config);

                    Ok(Arc::new(connection) as Arc<dyn LightDataAvailabilityLayer + Send + Sync>)
                }
                _ => Err(LightClientError::DALayer {
                    message: format!("Unsupported DA provider: {}", config.da_provider),
                }),
            }
        })?;

        // Create event channel
        let event_channel = EventChannel::new();
        let event_publisher = event_channel.publisher();
        let event_subscriber = event_channel.subscribe();

        // Create the light client
        let light_client = Arc::new(LightClient::new(
            da,
            config.start_height,
            config.prover_pubkey,
            event_publisher,
        ));

        // Start the light client
        let light_client_clone = light_client.clone();
        let runtime_clone = runtime.clone();
        std::thread::spawn(move || {
            if let Err(e) = runtime_clone.block_on(light_client_clone.run()) {
                eprintln!("Light client error: {}", e);
            }
        });

        Ok(Self {
            light_client,
            runtime,
            events_subscriber: Mutex::new(Some(event_subscriber)),
        })
    }

    pub fn get_current_commitment(&self) -> Result<Option<String>, LightClientError> {
        let result = self.runtime.block_on(self.light_client.get_latest_commitment());
        Ok(result.map(|c| c.to_string()))
    }

    pub fn next_event(&self) -> Result<UniffiLightClientEvent, LightClientError> {
        let mut events_subscriber = self.events_subscriber.lock().unwrap();
        match events_subscriber.as_mut() {
            Some(subscriber) => {
                let event = self.runtime.block_on(async {
                    subscriber.recv().await.map_err(|e| LightClientError::General {
                        message: format!("Failed to receive event: {}", e),
                    })
                })?;
                Ok(UniffiLightClientEvent::from(event))
            }
            None => Err(LightClientError::General {
                message: "Event subscriber not initialized".to_string(),
            }),
        }
    }
}

// Helper functions for the FFI layer
#[uniffi::export]
pub fn prism_light_client_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
