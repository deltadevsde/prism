use lumina_node::events::NodeEvent;
use prism_common::digest::Digest;
use serde::Serialize;
use std::fmt;
use tokio::sync::broadcast;
use web_time::SystemTime;

const EVENT_CHANNEL_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum LightClientEvent {
    SyncStarted { height: u64 },
    UpdateDAHeight { height: u64 },
    EpochVerificationStarted { height: u64 },
    EpochVerified { height: u64 },
    EpochVerificationFailed { height: u64, error: String },
    NoEpochFound { height: u64 },
    HeightChannelClosed,
    GetCurrentCommitment { commitment: Digest },

    LuminaEvent { event: NodeEvent },
    // maybe place for Future P2P events like
    /* ConnectingToFullNode {
        address: String,
    }, */
}

impl fmt::Display for LightClientEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LightClientEvent::SyncStarted { height } => {
                write!(f, "Starting sync at height {}", height)
            }
            LightClientEvent::UpdateDAHeight { height } => {
                write!(f, "Updated DA height to {}", height)
            }
            LightClientEvent::EpochVerificationStarted { height } => {
                write!(f, "Starting verification of epoch {}", height)
            }
            LightClientEvent::EpochVerified { height } => {
                write!(f, "Verified epoch {}", height)
            }
            LightClientEvent::EpochVerificationFailed { height, error } => {
                write!(f, "Failed to verify epoch {}: {}", height, error)
            }
            LightClientEvent::NoEpochFound { height } => {
                write!(f, "No epoch found for height {}", height)
            }
            LightClientEvent::HeightChannelClosed => {
                write!(f, "Height channel closed unexpectedly")
            }
            LightClientEvent::GetCurrentCommitment { commitment } => {
                write!(f, "Current commitment: {}", commitment)
            }
            LightClientEvent::LuminaEvent { event } => {
                write!(f, "Lumina event: {}", event)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EventInfo {
    pub event: LightClientEvent,
    pub time: SystemTime,
    pub formatted_log: String,
}

// The event channel that components use to broadcast events
#[derive(Debug)]
pub struct EventChannel {
    tx: broadcast::Sender<EventInfo>,
}

impl Default for EventChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl EventChannel {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self { tx }
    }

    pub fn publisher(&self) -> EventPublisher {
        EventPublisher {
            tx: self.tx.clone(),
        }
    }

    pub fn subscribe(&self) -> EventSubscriber {
        EventSubscriber {
            rx: self.tx.subscribe(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventPublisher {
    tx: broadcast::Sender<EventInfo>,
}

impl EventPublisher {
    pub fn send(&self, event: LightClientEvent) {
        let formatted_log = format!("{}", event);
        let event_info = EventInfo {
            event,
            time: SystemTime::now(),
            formatted_log,
        };
        let _ = self.tx.send(event_info);
    }
}

// Used by subscribers (like the WASM layer for nwo) to receive events
#[derive(Debug)]
pub struct EventSubscriber {
    rx: broadcast::Receiver<EventInfo>,
}

impl EventSubscriber {
    pub async fn recv(&mut self) -> Result<EventInfo, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
