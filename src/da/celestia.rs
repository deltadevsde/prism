use crate::{
    common::Operation,
    consts::CHANNEL_BUFFER_SIZE,
    da::{DataAvailabilityLayer, FinalizedEpoch},
    error::{DAResult, DataAvailabilityError, GeneralError},
};
use async_trait::async_trait;
use borsh::from_slice;
use celestia_rpc::{BlobClient, Client, HeaderClient};
use celestia_types::{blob::GasPrice, nmt::Namespace, Blob};
use std::{self, sync::Arc};
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::spawn,
};

impl TryFrom<&Blob> for FinalizedEpoch {
    type Error = GeneralError;

    fn try_from(value: &Blob) -> Result<Self, GeneralError> {
        from_slice::<Self>(&value.data)
            .map_err(|e| GeneralError::DecodingError(format!("decoding blob: {}", e)))
    }
}

impl TryFrom<&Blob> for Operation {
    type Error = GeneralError;

    fn try_from(value: &Blob) -> Result<Self, GeneralError> {
        from_slice::<Self>(&value.data)
            .map_err(|e| GeneralError::DecodingError(format!("decoding blob: {}", e)))
    }
}

pub struct CelestiaConnection {
    pub client: celestia_rpc::Client,
    pub snark_namespace: Namespace,
    pub operation_namespace: Namespace,

    synctarget_tx: Arc<Sender<u64>>,
    synctarget_rx: Arc<Mutex<Receiver<u64>>>,
}

impl CelestiaConnection {
    // TODO: Should take config
    pub async fn new(
        connection_string: &str,
        auth_token: Option<&str>,
        namespace_hex: &String,
    ) -> DAResult<Self> {
        let (tx, rx) = channel(CHANNEL_BUFFER_SIZE);

        let client = Client::new(connection_string, auth_token)
            .await
            .map_err(|e| {
                DataAvailabilityError::ConnectionError(format!(
                    "websocket initialization failed: {}",
                    e
                ))
            })?;

        let decoded_hex = match hex::decode(namespace_hex) {
            Ok(hex) => hex,
            Err(e) => {
                return Err(DataAvailabilityError::GeneralError(
                    GeneralError::DecodingError(format!(
                        "decoding namespace '{}': {}",
                        namespace_hex, e
                    )),
                ))
            }
        };

        let namespace_id = Namespace::new_v0(&decoded_hex).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::EncodingError(format!(
                "creating namespace '{}': {}",
                namespace_hex, e
            )))
        })?;

        Ok(CelestiaConnection {
            client,
            snark_namespace: namespace_id,
            // TODO: pass in second namespace
            operation_namespace: namespace_id,
            synctarget_tx: Arc::new(tx),
            synctarget_rx: Arc::new(Mutex::new(rx)),
        })
    }
}

#[async_trait]
impl DataAvailabilityLayer for CelestiaConnection {
    async fn get_latest_height(&self) -> DAResult<u64> {
        match self.synctarget_rx.lock().await.recv().await {
            Some(height) => Ok(height),
            None => Err(DataAvailabilityError::ChannelReceiveError),
        }
    }

    async fn initialize_sync_target(&self) -> DAResult<u64> {
        match HeaderClient::header_network_head(&self.client).await {
            Ok(extended_header) => Ok(extended_header.header.height.value()),
            Err(err) => Err(DataAvailabilityError::NetworkError(format!(
                "getting network head from da layer: {}",
                err
            ))),
        }
    }

    async fn get_snarks(&self, height: u64) -> DAResult<Vec<FinalizedEpoch>> {
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
                    Err(DataAvailabilityError::DataRetrievalError(
                        height,
                        format!("getting epoch from da layer: {}", err),
                    ))
                }
            }
        }
    }

    async fn submit_snarks(&self, epochs: Vec<FinalizedEpoch>) -> DAResult<u64> {
        if epochs.is_empty() {
            return Err(DataAvailabilityError::GeneralError(
                GeneralError::MissingArgumentError("No epochs provided for submission".to_string()),
            ));
        }

        debug!("posting {} epochs to da layer", epochs.len());

        let blobs: Result<Vec<Blob>, DataAvailabilityError> = epochs
            .iter()
            .map(|epoch| {
                let data = borsh::to_vec(epoch).map_err(|e| {
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

        let last_epoch_height = epochs.last().map(|e| e.height).unwrap_or(0);

        match self.client.blob_submit(&blobs, GasPrice::from(-1.0)).await {
            Ok(height) => Ok(height),
            Err(err) => Err(DataAvailabilityError::SubmissionError(
                last_epoch_height,
                err.to_string(),
            )),
        }
    }

    async fn get_operations(&self, height: u64) -> DAResult<Vec<Operation>> {
        trace!("searching for operations on da layer at height {}", height);
        match BlobClient::blob_get_all(&self.client, height, &[self.operation_namespace]).await {
            Ok(blobs) => {
                let mut operations = Vec::new();
                for blob in blobs.iter() {
                    match Operation::try_from(blob) {
                        Ok(operation) => operations.push(operation),
                        Err(_) => {
                            debug!(
                                "marshalling blob from height {} to operation failed: {:?}",
                                height, &blob
                            )
                        }
                    }
                }
                Ok(operations)
            }
            Err(err) => Err(DataAvailabilityError::DataRetrievalError(
                height,
                format!("getting operations from da layer: {}", err),
            )
            .into()),
        }
    }

    async fn submit_operations(&self, operations: Vec<Operation>) -> DAResult<u64> {
        debug!("posting {} operations to DA layer", operations.len());
        let blobs: Result<Vec<Blob>, DataAvailabilityError> = operations
            .iter()
            .map(|operation| {
                let data = borsh::to_vec(operation).map_err(|e| {
                    DataAvailabilityError::GeneralError(GeneralError::ParsingError(format!(
                        "serializing operation {}: {}",
                        operation, e
                    )))
                })?;
                Blob::new(self.operation_namespace, data).map_err(|e| {
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

        match self.client.blob_submit(&blobs, GasPrice::from(-1.0)).await {
            Ok(height) => Ok(height),
            Err(err) => Err(DataAvailabilityError::SubmissionError(
                // todo: fucking submission error is yikes, we need anyhow
                0,
                err.to_string(),
            )),
        }
    }

    async fn start(&self) -> DAResult<()> {
        let mut header_sub = HeaderClient::header_subscribe(&self.client)
            .await
            .map_err(|e| {
                DataAvailabilityError::NetworkError(format!(
                    "subscribing to headers from da layer: {}",
                    e
                ))
            })?;

        let synctarget_buffer = self.synctarget_tx.clone();
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
