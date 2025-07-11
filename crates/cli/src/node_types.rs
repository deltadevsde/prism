use anyhow::Result;
use async_trait::async_trait;
use prism_lightclient::LightClient;
use prism_prover::Prover;
use std::{self, sync::Arc};

#[async_trait]
pub trait NodeType {
    async fn start(self: Arc<Self>) -> Result<()>;
    // async fn stop(&self) -> Result<(), String>;
}

#[async_trait]
impl NodeType for Prover {
    async fn start(self: Arc<Self>) -> Result<()> {
        self.run().await
    }
}

#[async_trait]
impl NodeType for LightClient {
    async fn start(self: Arc<Self>) -> Result<()> {
        self.run().await
    }
}
