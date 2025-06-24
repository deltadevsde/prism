use lumina_node::events::{NodeEvent, EventSubscriber as LuminaEventSub};
use prism_common::digest::Digest;
use serde::Serialize;
use std::{fmt, sync::Arc};
use tokio::sync::{Mutex, broadcast};
use tracing::trace;
use web_time::SystemTime;

use crate::utils::spawn_task;

const EVENT_CHANNEL_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum PrismEvent {
    SyncStarted { height: u64 },
    UpdateDAHeight { height: u64 },
    EpochVerificationStarted { height: u64 },
    EpochVerified { height: u64 },
    EpochVerificationFailed { height: u64, error: String },
    NoEpochFound { height: u64 },
    HeightChannelClosed,
    GetCurrentCommitment { commitment: Digest },
    RecursiveVerificationStarted { height: u64 },
    RecursiveVerificationCompleted { height: u64 },

    LuminaEvent { event: NodeEvent },
    // maybe place for Future P2P events like
    /* ConnectingToFullNode {
        address: String,
    }, */
}

impl fmt::Display for PrismEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrismEvent::SyncStarted { height } => {
                write!(f, "Starting sync at height {}", height)
            }
            PrismEvent::UpdateDAHeight { height } => {
                write!(f, "Updated DA height to {}", height)
            }
            PrismEvent::EpochVerificationStarted { height } => {
                write!(f, "Starting verification of epoch {}", height)
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

    pub fn start_forwarding(&self, sub: Arc<Mutex<LuminaEventSub>>) {
        let publisher = self.publisher();
        spawn_task(async move {
            loop {
                let event = {
                    let mut subscriber = sub.lock().await;
                    subscriber.recv().await
                };
                match event {
                    Ok(event) => {
                        if let lumina_node::events::NodeEvent::AddedHeaderFromHeaderSub { height } =
                            event.event
                        {
                            publisher.send(PrismEvent::UpdateDAHeight { height });
                        } else {
                            #[cfg(target_arch = "wasm32")]
                            publisher.send(PrismEvent::LuminaEvent { event: event.event });

                            #[cfg(not(target_arch = "wasm32"))]
                            trace!("lumina event: {:?}", event);
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

impl From<Arc<Mutex<LuminaEventSub>>> for EventChannel {
    fn from(sub: Arc<Mutex<LuminaEventSub>>) -> Self {
        let chan = Self::new();
        chan.start_forwarding(sub);
        chan
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
