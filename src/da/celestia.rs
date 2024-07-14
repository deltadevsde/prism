use crate::da::{DataAvailabilityLayer, EpochJson};
use crate::{
    consts::CHANNEL_BUFFER_SIZE,
    error::{DAResult, DataAvailabilityError, GeneralError},
};
use async_trait::async_trait;
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

impl TryFrom<&Blob> for EpochJson {
    type Error = GeneralError;

    fn try_from(value: &Blob) -> Result<Self, GeneralError> {
        // convert blob data to utf8 string
        let data_str = String::from_utf8(value.data.clone()).map_err(|e| {
            GeneralError::EncodingError(format!("encoding blob data to utf8 string: {}", e))
        })?;

        serde_json::from_str(&data_str)
            .map_err(|e| GeneralError::DecodingError(format!("epoch json: {}", e)))
    }
}

pub struct CelestiaConnection {
    pub client: celestia_rpc::Client,
    pub namespace_id: Namespace,

    synctarget_tx: Arc<Sender<u64>>,
    synctarget_rx: Arc<Mutex<Receiver<u64>>>,
}

impl CelestiaConnection {
    // TODO: Should take config
    pub async fn new(
        connection_string: &String,
        auth_token: Option<&str>,
        namespace_hex: &String,
    ) -> DAResult<Self> {
        let (tx, rx) = channel(CHANNEL_BUFFER_SIZE);

        let client = Client::new(&connection_string, auth_token)
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
            namespace_id,
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

    async fn get(&self, height: u64) -> DAResult<Vec<EpochJson>> {
        trace!("searching for epoch on da layer at height {}", height);
        match BlobClient::blob_get_all(&self.client, height, &[self.namespace_id]).await {
            Ok(blobs) => {
                let mut epochs = Vec::new();
                for blob in blobs.iter() {
                    match EpochJson::try_from(blob) {
                        Ok(epoch_json) => epochs.push(epoch_json),
                        Err(_) => {
                            DataAvailabilityError::GeneralError(GeneralError::ParsingError(
                                format!(
                                    "marshalling blob from height {} to epoch json: {:?}",
                                    height, &blob
                                ),
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

    async fn submit(&self, epoch: &EpochJson) -> DAResult<u64> {
        debug!("posting epoch {} to da layer", epoch.height);

        let data = serde_json::to_string(&epoch).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::ParsingError(format!(
                "serializing epoch json: {}",
                e
            )))
        })?;
        let blob = Blob::new(self.namespace_id.clone(), data.into_bytes()).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::BlobCreationError(e.to_string()))
        })?;
        trace!("blob: {:?}", &blob);
        match self
            .client
            .blob_submit(&[blob.clone()], GasPrice::from(-1.0))
            .await
        {
            Ok(height) => Ok(height),
            Err(err) => Err(DataAvailabilityError::SubmissionError(
                epoch.height,
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
