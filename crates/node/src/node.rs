use crate::{
    consts::{CHANNEL_BUFFER_SIZE, DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    error::{DataAvailabilityError, DeimosResult},
};
use async_trait::async_trait;
use std::{sync::Arc};


#[async_trait]
pub trait NodeType {
    async fn start(self: Arc<Self>) -> DeimosResult<()>;
    // async fn stop(&self) -> Result<(), String>;
}
