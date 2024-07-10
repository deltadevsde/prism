
pub struct CelestiaConnection {
    pub client: celestia_rpc::Client,
    pub namespace_id: Namespace,

    synctarget_tx: Arc<Sender<u64>>,
    synctarget_rx: Arc<Mutex<Receiver<u64>>>,
}

#[async_trait]
impl DataAvailabilityLayer for CelestiaConnection {
    async fn get_message(&self) -> DAResult<u64> {
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
                                    "marshalling blob from height {} to epoch json: {}",
                                    height,
                                    serde_json::to_string(&blob).unwrap()
                                ),
                            ));
                        }
                    }
                }
                Ok(epochs)
            }
            Err(err) => Err(DataAvailabilityError::DataRetrievalError(
                height,
                format!("getting epoch from da layer: {}", err),
            )),
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
        debug!(
            "submitted blob with commitment {:?}",
            serde_json::to_string(&blob.clone().commitment).unwrap()
        );
        trace!("blob: {:?}", serde_json::to_string(&blob).unwrap());
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
