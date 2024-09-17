use crate::{
    cfg::CelestiaConfig,
    consts::CHANNEL_BUFFER_SIZE,
    da::{DataAvailabilityLayer, FinalizedEpoch},
};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use celestia_rpc::{BlobClient, Client, HeaderClient};
use celestia_types::{blob::GasPrice, nmt::Namespace, Blob};
use prism_common::operation::Operation;
use prism_errors::{DataAvailabilityError, GeneralError};
use std::{self, sync::Arc};
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::spawn,
};

use bincode;

impl TryFrom<&Blob> for FinalizedEpoch {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        bincode::deserialize(&value.data).context(format!(
            "Failed to decode blob into FinalizedEpoch: {value:?}"
        ))
    }
}

pub struct CelestiaConnection {
    pub client: celestia_rpc::Client,
    pub snark_namespace: Namespace,
    pub operation_namespace: Namespace,

    sync_target_tx: Arc<Sender<u64>>,
    sync_target_rx: Arc<Mutex<Receiver<u64>>>,
}

impl CelestiaConnection {
    pub async fn new(config: &CelestiaConfig, auth_token: Option<&str>) -> Result<Self> {
        let (tx, rx) = channel(CHANNEL_BUFFER_SIZE);

        let client = Client::new(&config.connection_string, auth_token)
            .await
            .context("Failed to initialize websocket connection")
            .map_err(|e| DataAvailabilityError::NetworkError(e.to_string()))?;

        let snark_namespace = create_namespace(&config.snark_namespace_id).context(format!(
            "Failed to create snark namespace from: '{}'",
            &config.snark_namespace_id
        ))?;

        let operation_namespace = match &config.operation_namespace_id {
            Some(id) => create_namespace(id).context(format!(
                "Failed to create operation namespace from: '{}'",
                id
            ))?,
            None => snark_namespace,
        };

        Ok(CelestiaConnection {
            client,
            snark_namespace,
            operation_namespace,
            sync_target_tx: Arc::new(tx),
            sync_target_rx: Arc::new(Mutex::new(rx)),
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
        match self.sync_target_rx.lock().await.recv().await {
            Some(height) => Ok(height),
            None => Err(anyhow!(DataAvailabilityError::ChannelReceiveError)),
        }
    }

    async fn initialize_sync_target(&self) -> Result<u64> {
        HeaderClient::header_network_head(&self.client)
            .await
            .context("Failed to get network head from DA layer")
            .map(|extended_header| extended_header.header.height.value())
    }

    async fn get_snarks(&self, height: u64) -> Result<Vec<FinalizedEpoch>> {
        trace!("searching for epoch on da layer at height {}", height);
        match BlobClient::blob_get_all(&self.client, height, &[self.snark_namespace]).await {
            Ok(blobs) => {
                let mut epochs = Vec::new();
                for blob in blobs.iter() {
                    match FinalizedEpoch::try_from(blob) {
                        Ok(epoch_json) => epochs.push(epoch_json),
                        Err(_) => {
                            GeneralError::ParsingError(format!(
                                "marshalling blob from height {} to epoch json: {:?}",
                                height, &blob
                            ));
                        }
                    }
                }
                Ok(epochs)
            }
            Err(err) => {
                // todo: this is a hack to handle a retarded error from cel-node that will be fixed in v0.15.0
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

    async fn submit_snarks(&self, epochs: Vec<FinalizedEpoch>) -> Result<u64> {
        if epochs.is_empty() {
            bail!("no epochs provided for submission");
        }

        debug!("posting {} epochs to da layer", epochs.len());

        let blobs: Result<Vec<Blob>, DataAvailabilityError> = epochs
            .iter()
            .map(|epoch| {
                let data = bincode::serialize(epoch).map_err(|e| {
                    DataAvailabilityError::GeneralError(GeneralError::ParsingError(format!(
                        "serializing epoch {}: {}",
                        epoch.height, e
                    )))
                })?;
                Blob::new(self.snark_namespace, data).map_err(|e| {
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
            .blob_submit(&blobs, GasPrice::from(-1.0))
            .await
            .map_err(|e| anyhow!(DataAvailabilityError::SubmissionError(e.to_string())))
    }

    async fn get_operations(&self, height: u64) -> Result<Vec<Operation>> {
        trace!("searching for operations on da layer at height {}", height);
        let blobs = BlobClient::blob_get_all(&self.client, height, &[self.operation_namespace])
            .await
            .map_err(|e| {
                anyhow!(DataAvailabilityError::DataRetrievalError(
                    height,
                    e.to_string()
                ))
            })?;

        let operations = blobs
            .iter()
            .filter_map(|blob| match Operation::try_from(blob) {
                Ok(operation) => Some(operation),
                Err(e) => {
                    warn!(
                        "Failed to parse blob from height {} to operation: {:?}",
                        height, e
                    );
                    None
                }
            })
            .collect();

        Ok(operations)
    }

    async fn submit_operations(&self, operations: Vec<Operation>) -> Result<u64> {
        debug!("posting {} operations to DA layer", operations.len());
        let blobs: Result<Vec<Blob>, _> = operations
            .iter()
            .map(|operation| {
                let data = bincode::serialize(operation)
                    .context(format!("Failed to serialize operation {}", operation))
                    .map_err(|e| {
                        DataAvailabilityError::GeneralError(GeneralError::ParsingError(
                            e.to_string(),
                        ))
                    })?;

                Blob::new(self.operation_namespace, data)
                    .context(format!("Failed to create blob for operation {}", operation))
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
            .blob_submit(&blobs, GasPrice::from(-1.0))
            .await
            .map_err(|e| anyhow!(DataAvailabilityError::SubmissionError(e.to_string())))
    }

    async fn start(&self) -> Result<()> {
        let mut header_sub = HeaderClient::header_subscribe(&self.client)
            .await
            .context("Failed to subscribe to headers from DA layer")
            .map_err(|e| DataAvailabilityError::NetworkError(e.to_string()))?;

        let synctarget_buffer = self.sync_target_tx.clone();
        spawn(async move {
            while let Some(extended_header_result) = header_sub.next().await {
                match extended_header_result {
                    Ok(extended_header) => {
                        let height = extended_header.header.height.value();
                        match synctarget_buffer.send(height).await {
                            Ok(_) => {
                                debug!("sent sync target update for height {}", height);
                            }
                            Err(_) => {
                                DataAvailabilityError::SyncTargetError(format!(
                                    "sending sync target update message for height {}",
                                    height
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        DataAvailabilityError::NetworkError(format!(
                            "retrieving header from da layer: {}",
                            e
                        ));
                    }
                }
            }
        });
        Ok(())
    }
}
