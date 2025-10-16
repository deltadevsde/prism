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
pub enum PrismEvent {
    /// Sent when the node is ready to sync and listening to new events.
    Ready,
    /// Sent when backwards sync starts at the given DA height.
    HistoricalSyncStarted { height: u64 },
    /// Sent when the historical sync completes. Is None when the sync did not find any
    /// [`FinalizedEpoch`]s.
    HistoricalSyncCompleted { height: Option<u64> },
    /// Sent when the DA height is updated to the given height.
    UpdateDAHeight { height: u64 },
    /// Sent when the Epoch Verification was successfully verified at given height.
    EpochVerified { height: u64 },
    /// Sent when a [`FinalizedEpoch`] fails validation. Gives the height it failed at and the
    /// error.
    EpochVerificationFailed { height: u64, error: String },
    /// Sent when a DA height is queried and no [`FinalizedEpoch`] is found. Gives the
    /// height it failed at.
    NoEpochFound { height: u64 },
    /// Sent when the DA Height Channel closes unexpectedly.
    HeightChannelClosed,
    /// Sent when the current Commitment is retrieved. Gives the commitment retrieved.
    GetCurrentCommitment { commitment: Digest },
    /// Sent when Recursive Verification starts at the given height.
    RecursiveVerificationStarted { height: u64 },
    /// Sent when Epoch Verification completes at a given height.
    RecursiveVerificationCompleted { height: u64 },

    /// Forwarded events from Lumina.
    LuminaEvent { event: NodeEvent },
    // maybe place for Future P2P events like
    /* ConnectingToFullNode {
        address: String,
    }, */
}

impl fmt::Display for PrismEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrismEvent::Ready => {
                write!(
                    f,
                    "Node is ready to start sync and listening for incoming headers"
                )
            }
            PrismEvent::HistoricalSyncStarted { height } => {
                write!(f, "Starting historical sync at height {}", height)
            }
            PrismEvent::HistoricalSyncCompleted { height } => {
                write!(
                    f,
                    "Historical sync complete, found epoch: {}",
                    height.is_some()
                )
            }
            PrismEvent::UpdateDAHeight { height } => {
                write!(f, "Updated DA height to {}", height)
            }
            PrismEvent::EpochVerified { height } => {
                write!(f, "Verified epoch {}", height)
            }
            PrismEvent::EpochVerificationFailed { height, error } => {
                write!(f, "Failed to verify epoch {}: {}", height, error)
            }
            PrismEvent::NoEpochFound { height } => {
                write!(f, "No epoch found for height {}", height)
            }
            PrismEvent::HeightChannelClosed => {
                write!(f, "Height channel closed unexpectedly")
            }
            PrismEvent::GetCurrentCommitment { commitment } => {
                write!(f, "Current commitment: {}", commitment)
            }
            PrismEvent::RecursiveVerificationStarted { height } => {
                write!(f, "Starting recursive verification at height {}", height)
            }
            PrismEvent::RecursiveVerificationCompleted { height } => {
                write!(f, "Completed recursive verification at height {}", height)
            }
            PrismEvent::LuminaEvent { event } => {
                write!(f, "Lumina event: {}", event)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EventInfo {
    pub event: PrismEvent,
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
    pub fn send(&self, event: PrismEvent) {
        let formatted_log = event.to_string();
        let event_info = EventInfo {
            event,
            time: SystemTime::now(),
            formatted_log,
        };
        let _ = self.tx.send(event_info);
    }
}

#[derive(Debug)]
pub struct EventSubscriber {
    rx: broadcast::Receiver<EventInfo>,
}

impl EventSubscriber {
    pub async fn recv(&mut self) -> Result<EventInfo, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
