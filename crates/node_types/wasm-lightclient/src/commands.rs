use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum LightClientCommand {
    GetCurrentCommitment,
    GetEventsChannelName,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    CurrentCommitment(String),
    EventsChannelName(String),
    Error(String),
}
