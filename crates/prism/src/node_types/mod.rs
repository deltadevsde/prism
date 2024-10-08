use anyhow::Result;
use async_trait::async_trait;
use std::{self, sync::Arc};

pub mod lightclient;

#[async_trait]
pub trait NodeType {
    async fn start(self: Arc<Self>) -> Result<()>;
    // async fn stop(&self) -> Result<(), String>;
}

#[async_trait]
impl NodeType for prism_sequencer::Sequencer {
    async fn start(self: Arc<Self>) -> Result<()> {
        self.start().await
    }
}
