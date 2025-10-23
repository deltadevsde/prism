use core::fmt;
use lumina_node::events::NodeEvent;
use serde::Serialize;
use std::time::SystemTime;

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
    /// Sent when syncing with the DA layer fails.
    SyncFailed { error: String },
    /// Sent when the DA height is updated to the given height.
    UpdateDAHeight { height: u64 },
    /// Sent when the connection to the DA layer is lost.
    DAConnectionLost { error: String },
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
    /// Sent when Recursive Verification starts at the given height.
    RecursiveVerificationStarted { height: u64 },
    /// Sent when Epoch Verification completes at a given height.
    RecursiveVerificationCompleted { height: u64 },

    /// Forwarded events from Lumina.
    LuminaEvent { event: NodeEvent },
    /// Sent when an unspecific error occurs during operation.
    OperationError { error: String },
    // maybe place for Future P2P events like
    /* ConnectingToFullNode {
        address: String,
    }, */
}

impl PrismEvent {
    pub fn is_error(&self) -> bool {
        match self {
            Self::EpochVerificationFailed { .. }
            | Self::HeightChannelClosed
            | Self::DAConnectionLost { .. }
            | Self::SyncFailed { .. }
            | Self::OperationError { .. } => true,
            Self::LuminaEvent { event } => event.is_error(),
            _ => false,
        }
    }
}

impl fmt::Display for PrismEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => {
                write!(
                    f,
                    "Node is ready to start sync and listening for incoming headers"
                )
            }
            Self::HistoricalSyncStarted { height } => {
                write!(f, "Starting historical sync at height {}", height)
            }
            Self::HistoricalSyncCompleted { height } => {
                write!(
                    f,
                    "Historical sync complete, found epoch: {}",
                    height.is_some()
                )
            }
            Self::SyncFailed { error } => {
                write!(f, "Sync with the DA layer failed: {}", error)
            }
            Self::UpdateDAHeight { height } => {
                write!(f, "Updated DA height to {}", height)
            }
            Self::DAConnectionLost { error } => {
                write!(f, "DA connection lost: {}", error)
            }
            Self::EpochVerified { height } => {
                write!(f, "Verified epoch {}", height)
            }
            Self::EpochVerificationFailed { height, error } => {
                write!(f, "Failed to verify epoch {}: {}", height, error)
            }
            Self::NoEpochFound { height } => {
                write!(f, "No epoch found for height {}", height)
            }
            Self::HeightChannelClosed => {
                write!(f, "Height channel closed unexpectedly")
            }
            Self::RecursiveVerificationStarted { height } => {
                write!(f, "Starting recursive verification at height {}", height)
            }
            Self::RecursiveVerificationCompleted { height } => {
                write!(f, "Completed recursive verification at height {}", height)
            }
            Self::LuminaEvent { event } => {
                write!(f, "Lumina event: {}", event)
            }
            Self::OperationError { error } => {
                write!(f, "Operation error: {}", error)
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

impl EventInfo {
    pub fn is_error(&self) -> bool {
        self.event.is_error()
    }
}
