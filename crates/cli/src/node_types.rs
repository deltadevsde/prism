use anyhow::Result;
use async_trait::async_trait;
use prism_lightclient::LightClient;
use prism_prover::Prover;

#[async_trait]
pub trait NodeType: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
}

#[async_trait]
impl NodeType for Prover {
    async fn start(&self) -> Result<()> {
        Self::start(self).await
    }

    async fn stop(&self) -> Result<()> {
        Self::stop(self).await
    }
}

#[async_trait]
impl NodeType for LightClient {
    async fn start(&self) -> Result<()> {
        Self::start(self).await
    }

    async fn stop(&self) -> Result<()> {
        Self::stop(self).await
    }
}
