use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum LightClientCommand {
    VerifyEpoch { height: u64 },
    GetCurrentHeight,
    SetProverKey(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    EpochVerified,
    CurrentHeight(u64),
    ProverKeySet,
    Error(String),
}
