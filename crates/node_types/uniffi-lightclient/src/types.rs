use prism_da::events::LightClientEvent;

/// Event types emitted by the LightClient.
#[derive(uniffi::Enum)]
pub enum UniffiLightClientEvent {
    /// Sync has started at a specific height
    SyncStarted {
        /// The height at which sync started
        height: u64,
    },
    /// DA layer height has been updated
    UpdateDAHeight {
        /// The new DA layer height
        height: u64,
    },
    /// Epoch verification has started
    EpochVerificationStarted {
        /// The epoch height being verified
        height: u64,
    },
    /// Epoch was successfully verified
    EpochVerified {
        /// The epoch height that was verified
        height: u64,
    },
    /// Epoch verification failed
    EpochVerificationFailed {
        /// The epoch height that failed verification
        height: u64,
        /// Error message
        error: String,
    },
    /// No epoch was found at the specified height
    NoEpochFound {
        /// The height at which no epoch was found
        height: u64,
    },
    /// Height channel was closed
    HeightChannelClosed,
    /// Current commitment retrieved
    GetCurrentCommitment {
        /// The current commitment
        commitment: String,
    },
    /// Recursive verification started
    RecursiveVerificationStarted {
        /// The height at which recursive verification started
        height: u64,
    },
    /// Recursive verification completed
    RecursiveVerificationCompleted {
        /// The height at which recursive verification completed
        height: u64,
    },
    /// Node event from Lumina
    LuminaEvent {
        /// The original event string
        event: String,
    },
}

impl From<LightClientEvent> for UniffiLightClientEvent {
    fn from(event: LightClientEvent) -> Self {
        match event {
            LightClientEvent::SyncStarted { height } => {
                UniffiLightClientEvent::SyncStarted { height }
            }
            LightClientEvent::UpdateDAHeight { height } => {
                UniffiLightClientEvent::UpdateDAHeight { height }
            }
            LightClientEvent::EpochVerificationStarted { height } => {
                UniffiLightClientEvent::EpochVerificationStarted { height }
            }
            LightClientEvent::EpochVerified { height } => {
                UniffiLightClientEvent::EpochVerified { height }
            }
            LightClientEvent::EpochVerificationFailed { height, error } => {
                UniffiLightClientEvent::EpochVerificationFailed { height, error }
            }
            LightClientEvent::NoEpochFound { height } => {
                UniffiLightClientEvent::NoEpochFound { height }
            }
            LightClientEvent::HeightChannelClosed => UniffiLightClientEvent::HeightChannelClosed,
            LightClientEvent::GetCurrentCommitment { commitment } => {
                UniffiLightClientEvent::GetCurrentCommitment {
                    commitment: commitment.to_string(),
                }
            }
            LightClientEvent::RecursiveVerificationStarted { height } => {
                UniffiLightClientEvent::RecursiveVerificationStarted { height }
            }
            LightClientEvent::RecursiveVerificationCompleted { height } => {
                UniffiLightClientEvent::RecursiveVerificationCompleted { height }
            }
            LightClientEvent::LuminaEvent { event } => UniffiLightClientEvent::LuminaEvent {
                event: event.to_string(),
            },
        }
    }
}
