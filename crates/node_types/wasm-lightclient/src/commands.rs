use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum LightClientCommand {
    VerifyEpoch { height: u64 },
    GetCurrentHeight,
    SetProverKey(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    EpochVerified(bool),
    CurrentHeight(u64),
    ProverKeySet,
    SamplingResult { height: u64, accepted: bool },
    NoEpochFound { height: u64 },
    Error(String),
    Ignored,
}
