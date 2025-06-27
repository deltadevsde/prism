#![cfg(not(target_arch = "wasm32"))]

use crate::{
    FinalizedEpoch, LightDataAvailabilityLayer, VerifiableEpoch,
    events::{EventChannel, PrismEvent},
};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use celestia_types::{Blob, nmt::Namespace};
use prism_errors::{DataAvailabilityError, GeneralError};
use std::{
    self,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{error, trace};

use tokio::sync::broadcast;

use crate::DataAvailabilityLayer;
use celestia_rpc::{BlobClient, Client, HeaderClient, TxConfig};
use celestia_types::AppVersion;
use prism_common::transaction::Transaction;
use prism_serde::binary::ToBinary;
use tokio::task::spawn;
use tracing::{debug, warn};

use super::utils::{CelestiaConfig, create_namespace};

pub struct CelestiaConnection {
    pub client: celestia_rpc::Client,
    pub snark_namespace: Namespace,
    pub operation_namespace: Namespace,

    height_update_tx: broadcast::Sender<u64>,
    sync_target: Arc<AtomicU64>,
    event_channel: Arc<EventChannel>,
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

        let operation_namespace =
            create_namespace(&config.operation_namespace_id).context(format!(
                "Failed to create operation namespace from: '{}'",
                &config.operation_namespace_id
            ))?;

        let (height_update_tx, _) = broadcast::channel(100);
        let event_channel = Arc::new(EventChannel::new());

        Ok(CelestiaConnection {
            client,
            snark_namespace,
            operation_namespace,
            height_update_tx,
            sync_target: Arc::new(AtomicU64::new(0)),
            event_channel,
        })
    }
}

#[async_trait]
impl LightDataAvailabilityLayer for CelestiaConnection {
    async fn get_finalized_epoch(&self, height: u64) -> Result<Vec<VerifiableEpoch>> {
        trace!("searching for epoch on da layer at height {}", height);

        match BlobClient::blob_get_all(&self.client, height, &[self.snark_namespace]).await {
            Ok(maybe_blobs) => match maybe_blobs {
                Some(blobs) => {
                    let valid_epochs: Vec<VerifiableEpoch> = blobs
                        .into_iter()
                        .filter_map(|blob| {
                            match FinalizedEpoch::try_from(&blob) {
                                Ok(epoch) => Some(Box::new(epoch) as VerifiableEpoch),
                                Err(e) => {
                                    warn!(
                                        "Ignoring blob: marshalling blob from height {} to epoch json failed with error {}: {:?}",
                                        height, e, &blob
                                    );
                                    None
                                }
                            }
                        })
                        .collect();
                    Ok(valid_epochs)
                }
                None => Ok(vec![]),
            },
            Err(err) => {
                if err.to_string().contains("blob: not found") {
                    Ok(vec![])
                } else {
                    Err(anyhow!(DataAvailabilityError::DataRetrievalError(
                        height,
                        format!("getting epoch from da layer: {}", err)
                    )))
                }
            }
        }
    }

    fn event_channel(&self) -> Arc<EventChannel> {
        self.event_channel.clone()
    }
}

#[async_trait]
impl DataAvailabilityLayer for CelestiaConnection {
    async fn start(&self) -> Result<()> {
        let mut header_sub = HeaderClient::header_subscribe(&self.client)
            .await
            .context("Failed to subscribe to headers from DA layer")?;

        let sync_target = self.sync_target.clone();
        let height_update_tx = self.height_update_tx.clone();
        let event_publisher = self.event_channel.publisher();

        spawn(async move {
            while let Some(extended_header_result) = header_sub.next().await {
                match extended_header_result {
                    Ok(extended_header) => {
                        let height = extended_header.header.height.value();
                        sync_target.store(height, Ordering::Relaxed);
                        // todo: correct error handling
                        let _ = height_update_tx.send(height);
                        trace!("updated sync target for height {}", height);

                        event_publisher.send(PrismEvent::UpdateDAHeight { height });
                    }
                    Err(e) => {
                        error!("Error retrieving header from DA layer: {}", e);
                    }
                }
            }
        });
        Ok(())
    }

    fn subscribe_to_heights(&self) -> broadcast::Receiver<u64> {
        self.height_update_tx.subscribe()
    }

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

    async fn submit_finalized_epoch(&self, epoch: FinalizedEpoch) -> Result<u64> {
        let data = epoch.encode_to_bytes().map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::ParsingError(format!(
                "serializing epoch {}: {}",
                epoch.height, e
            )))
        })?;

        debug!(
            "posting {}th epoch to da layer ({} bytes)",
            epoch.height,
            data.len()
        );

        debug!("epoch: {:?}", epoch);

        let blob = Blob::new(self.snark_namespace, data, AppVersion::V3).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::BlobCreationError(e.to_string()))
        })?;

        self.client
            .blob_submit(&[blob], TxConfig::default())
            .await
            .map_err(|e| anyhow!(DataAvailabilityError::SubmissionError(e.to_string())))
    }

    async fn get_transactions(&self, height: u64) -> Result<Vec<Transaction>> {
        trace!(
            "searching for transactions on da layer at height {}",
            height
        );
        let maybe_blobs =
            BlobClient::blob_get_all(&self.client, height, &[self.operation_namespace])
                .await
                .map_err(|e| {
                    anyhow!(DataAvailabilityError::DataRetrievalError(
                        height,
                        format!("getting transactions from da layer: {}", e)
                    ))
                })?;

        let blobs = match maybe_blobs {
            Some(blobs) => blobs,
            None => return Ok(vec![]),
        };

        let transactions = blobs
            .iter()
            .filter_map(|blob| match Transaction::try_from(blob) {
                Ok(transaction) => Some(transaction),
                Err(e) => {
                    warn!(
                        "Failed to parse blob from height {} to transaction: {:?}",
                        height, e
                    );
                    None
                }
            })
            .collect();

        Ok(transactions)
    }

    async fn submit_transactions(&self, transactions: Vec<Transaction>) -> Result<u64> {
        debug!("posting {} transactions to DA layer", transactions.len());
        let blobs: Result<Vec<Blob>, _> = transactions
            .iter()
            .map(|transaction| {
                let data = transaction
                    .encode_to_bytes()
                    .context(format!("Failed to serialize transaction {:?}", transaction))
                    .map_err(|e| {
                        DataAvailabilityError::GeneralError(GeneralError::ParsingError(
                            e.to_string(),
                        ))
                    })?;

                Blob::new(self.operation_namespace, data, AppVersion::V3)
                    .context(format!(
                        "Failed to create blob for transaction {:?}",
                        transaction
                    ))
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
}
