use anyhow::Result;
use async_trait::async_trait;
use std::{self, sync::Arc, time::Duration};
use tokio::time::sleep;

#[async_trait]
pub trait NodeType {
    async fn start(self: Arc<Self>) -> Result<()>;
    // async fn stop(&self) -> Result<(), String>;
}

#[async_trait]
impl NodeType for prism_prover::Prover {
    async fn start(self: Arc<Self>) -> Result<()> {
        self.run().await
    }
}

#[async_trait]
impl NodeType for prism_lightclient::LightClient {
    async fn start(self: Arc<Self>) -> Result<()> {
        self.run().await
    }
}
