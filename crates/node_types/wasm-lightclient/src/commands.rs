use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum LightClientCommand {
    VerifyEpoch { height: u64 },
    GetCurrentHeight,
    GetAccount(String), // account id
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    EpochVerified { verified: bool, height: u64 },
    CurrentHeight(u64),
    GetAccount(Option<String>), // TODO: get real account (AccountResponse or smth)
    SamplingResult { height: u64, accepted: bool },
    NoEpochFound { height: u64 },
    Error(String),
    Ignored,
}
