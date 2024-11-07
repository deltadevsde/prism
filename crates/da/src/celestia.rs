use crate::{DataAvailabilityLayer, FinalizedEpoch};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use celestia_rpc::{BlobClient, Client, HeaderClient};
use celestia_types::{nmt::Namespace, Blob, TxConfig};
use log::{debug, error, trace, warn};
use prism_common::request::PendingRequest;
use prism_errors::{DataAvailabilityError, GeneralError};
use serde::{Deserialize, Serialize};
use std::{
    self,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::{sync::broadcast, task::spawn};

use bincode;

impl TryFrom<&Blob> for FinalizedEpoch {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        bincode::deserialize(&value.data).context(format!(
            "Failed to decode blob into FinalizedEpoch: {value:?}"
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CelestiaConfig {
    pub connection_string: String,
    pub start_height: u64,
    pub snark_namespace_id: String,
    pub request_namespace_id: Option<String>,
}

impl Default for CelestiaConfig {
    fn default() -> Self {
        CelestiaConfig {
            connection_string: "ws://localhost:26658".to_string(),
            start_height: 0,
            snark_namespace_id: "00000000000000de1008".to_string(),
            request_namespace_id: Some("00000000000000de1009".to_string()),
        }
    }
}

pub struct CelestiaConnection {
    pub client: celestia_rpc::Client,
    pub snark_namespace: Namespace,
    pub request_namespace: Namespace,

    height_update_tx: broadcast::Sender<u64>,
    sync_target: Arc<AtomicU64>,
}

impl CelestiaConnection {
    pub async fn new(config: &CelestiaConfig, auth_token: Option<&str>) -> Result<Self> {
        let client = Client::new(&config.connection_string, auth_token)
            .await
            .context("Failed to initialize websocket connection")
            .map_err(|e| DataAvailabilityError::NetworkError(e.to_string()))?;

        let snark_namespace = create_namespace(&config.snark_namespace_id).context(format!(
            "Failed to create snark namespace from: '{}'",
            &config.snark_namespace_id
        ))?;

        let request_namespace = match &config.request_namespace_id {
            Some(id) => create_namespace(id).context(format!(
                "Failed to create operation namespace from: '{}'",
                id
            ))?,
            None => snark_namespace,
        };

        let (height_update_tx, _) = broadcast::channel(100);

        Ok(CelestiaConnection {
            client,
            snark_namespace,
            request_namespace,
            height_update_tx,
            sync_target: Arc::new(AtomicU64::new(0)),
        })
    }
}

fn create_namespace(namespace_hex: &str) -> Result<Namespace> {
    let decoded_hex = hex::decode(namespace_hex).context(format!(
        "Failed to decode namespace hex '{}'",
        namespace_hex
    ))?;

    Namespace::new_v0(&decoded_hex).context(format!(
        "Failed to create namespace from '{}'",
        namespace_hex
    ))
}

#[async_trait]
impl DataAvailabilityLayer for CelestiaConnection {
    async fn get_latest_height(&self) -> Result<u64> {
        Ok(self.sync_target.load(Ordering::Relaxed))
    }

    async fn initialize_sync_target(&self) -> Result<u64> {
        let height = HeaderClient::header_network_head(&self.client)
            .await
            .context("Failed to get network head from DA layer")
            .map(|extended_header| extended_header.header.height.value())?;

        self.sync_target.store(height, Ordering::Relaxed);
        Ok(height)
    }

    async fn get_finalized_epoch(&self, height: u64) -> Result<Option<FinalizedEpoch>> {
        trace!("searching for epoch on da layer at height {}", height);

        match BlobClient::blob_get_all(&self.client, height, &[self.snark_namespace]).await {
            Ok(maybe_blobs) => match maybe_blobs {
                Some(blobs) => blobs
                    .into_iter()
                    .next()
                    .map(|blob| {
                        FinalizedEpoch::try_from(&blob).map_err(|_| {
                            anyhow!(GeneralError::ParsingError(format!(
                                "marshalling blob from height {} to epoch json: {:?}",
                                height, &blob
                            )))
                        })
                    })
                    .transpose(),
                None => Ok(None),
            },
            Err(err) => {
                if err.to_string().contains("blob: not found") {
                    Ok(None)
                } else {
                    Err(anyhow!(DataAvailabilityError::DataRetrievalError(
                        height,
                        format!("getting epoch from da layer: {}", err)
                    )))
                }
            }
        }
    }

    async fn submit_finalized_epoch(&self, epoch: FinalizedEpoch) -> Result<u64> {
        debug!("posting {}th epoch to da layer", epoch.height);

        let data = bincode::serialize(&epoch).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::ParsingError(format!(
                "serializing epoch {}: {}",
                epoch.height, e
            )))
        })?;

        let blob = Blob::new(self.snark_namespace, data).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::BlobCreationError(e.to_string()))
        })?;

        self.client
            .blob_submit(&[blob], TxConfig::default())
            .await
            .map_err(|e| anyhow!(DataAvailabilityError::SubmissionError(e.to_string())))
    }

    async fn get_requests(&self, height: u64) -> Result<Vec<PendingRequest>> {
        trace!("searching for operations on da layer at height {}", height);
        let maybe_blobs = BlobClient::blob_get_all(&self.client, height, &[self.request_namespace])
            .await
            .map_err(|e| {
                anyhow!(DataAvailabilityError::DataRetrievalError(
                    height,
                    format!("getting operations from da layer: {}", e)
                ))
            })?;

        let blobs = match maybe_blobs {
            Some(blobs) => blobs,
            None => return Ok(vec![]),
        };

        let requests = blobs
            .iter()
            .filter_map(|blob| match PendingRequest::try_from(blob) {
                Ok(request) => Some(request),
                Err(e) => {
                    warn!(
                        "Failed to parse blob from height {} to operation: {:?}",
                        height, e
                    );
                    None
                }
            })
            .collect();

        Ok(requests)
    }

    async fn submit_requests(&self, requests: Vec<PendingRequest>) -> Result<u64> {
        debug!("posting {} entries to DA layer", requests.len());
        let blobs: Result<Vec<Blob>, _> = requests
            .iter()
            .map(|request| {
                let data = bincode::serialize(request)
                    .context(format!("Failed to serialize entry {:?}", request))
                    .map_err(|e| {
                        DataAvailabilityError::GeneralError(GeneralError::ParsingError(
                            e.to_string(),
                        ))
                    })?;

                Blob::new(self.request_namespace, data)
                    .context(format!("Failed to create blob for entry {:?}", request))
                    .map_err(|e| {
                        DataAvailabilityError::GeneralError(GeneralError::BlobCreationError(
                            e.to_string(),
                        ))
                    })
            })
            .collect();

        let blobs = blobs?;

        for (i, blob) in blobs.iter().enumerate() {
            trace!("blob {}: {:?}", i, blob);
        }

        self.client
            .blob_submit(&blobs, TxConfig::default())
            .await
            .map_err(|e| anyhow!(DataAvailabilityError::SubmissionError(e.to_string())))
    }

    fn subscribe_to_heights(&self) -> broadcast::Receiver<u64> {
        self.height_update_tx.subscribe()
    }

    async fn start(&self) -> Result<()> {
        let mut header_sub = HeaderClient::header_subscribe(&self.client)
            .await
            .context("Failed to subscribe to headers from DA layer")?;

        let sync_target = self.sync_target.clone();
        let height_update_tx = self.height_update_tx.clone();

        spawn(async move {
            while let Some(extended_header_result) = header_sub.next().await {
                match extended_header_result {
                    Ok(extended_header) => {
                        let height = extended_header.header.height.value();
                        sync_target.store(height, Ordering::Relaxed);
                        // todo: correct error handling
                        let _ = height_update_tx.send(height);
                        trace!("updated sync target for height {}", height);
                    }
                    Err(e) => {
                        error!("Error retrieving header from DA layer: {}", e);
                    }
                }
            }
        });
        Ok(())
    }
}
