use crate::error::PrismResult;
use async_trait::async_trait;
use std::{self, sync::Arc};

pub mod lightclient;
pub mod sequencer;

#[async_trait]
pub trait NodeType {
    async fn start(self: Arc<Self>) -> PrismResult<()>;
    // async fn stop(&self) -> Result<(), String>;
}
