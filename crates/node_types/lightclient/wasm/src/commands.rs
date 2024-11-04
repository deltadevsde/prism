use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum LightClientCommand {
    InternalPing, // i dont know if we need them....RYAANAAAAAN
    VerifyEpoch { height: u64 },
    GetCurrentHeight,
    SetProverKey(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    InternalPong, // i dont know if we need them....RYAANAAAAAN
    EpochVerified,
    CurrentHeight(u64),
    ProverKeySet,
    Error(String),
}
