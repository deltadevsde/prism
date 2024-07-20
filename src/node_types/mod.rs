use crate::error::DeimosResult;
use async_trait::async_trait;
use std::{self, sync::Arc};

pub mod lightclient;
pub mod sequencer;

#[async_trait]
pub trait NodeType {
    async fn start(self: Arc<Self>) -> DeimosResult<()>;
    // async fn stop(&self) -> Result<(), String>;
}
