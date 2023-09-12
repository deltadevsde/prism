use crate::zk_snark::{Bls12Proof, VerifyingKey};
use actix_web::rt::spawn;
use async_trait::async_trait;
use celestia_rpc::{client::new_websocket, BlobClient, HeaderClient};
use celestia_types::{nmt::Namespace, Blob};
use jsonrpsee::ws_client::WsClient;
use serde::{Deserialize, Serialize};
use std::{self, sync::Arc};
use tokio::sync::mpsc;

// TODO: Add signature from sequencer for lc to verify (#2)
#[derive(Serialize, Deserialize)]
pub struct EpochJson {
    pub height: u64,
    pub prev_commitment: String,
    pub current_commitment: String,
    pub proof: Bls12Proof,
    pub verifying_key: VerifyingKey,
}

impl TryFrom<&Blob> for EpochJson {
    type Error = ();

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        match serde_json::from_str::<EpochJson>(
            String::from_utf8(value.data.clone()).unwrap().as_str(),
        ) {
            Ok(epoch_json) => Ok(epoch_json),
            Err(e) => Err(()),
        }
    }
}

enum Message {
    UpdateTarget(u64),
}

#[async_trait]
pub trait DataAvailabilityLayer: Send + Sync {
    async fn get_message(&self) -> Result<u64, String>;
    async fn initialize_sync_target(&self) -> Result<u64, String>;
    async fn get(&self, height: u64) -> Result<Vec<EpochJson>, String>;
    async fn submit(&self, epoch: &EpochJson) -> Result<u64, String>;
    async fn start(&self) -> Result<(), String>;
}

pub struct CelestiaConnection {
    pub client: WsClient,
    pub namespace_id: Namespace,
    tx: Arc<mpsc::Sender<Message>>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Message>>>,
}

impl CelestiaConnection {
    // TODO: Should take config
    pub async fn new(
        connection_string: &String,
        auth_token: Option<&str>,
        namespace_hex: &String,
    ) -> CelestiaConnection {
        let (tx, rx) = mpsc::channel(5);

        CelestiaConnection {
            client: new_websocket(&connection_string, auth_token).await.unwrap(),
            namespace_id: Namespace::new_v0(&hex::decode(namespace_hex).unwrap()).unwrap(),
            tx: Arc::new(tx),
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
        }
    }
}

#[async_trait]
impl DataAvailabilityLayer for CelestiaConnection {
    async fn get_message(&self) -> Result<u64, String> {
        match self.rx.lock().await.recv().await {
            Some(Message::UpdateTarget(height)) => Ok(height),
            None => Err(format!("Could not get message from channel: FUCK")),
        }
    }

    async fn initialize_sync_target(&self) -> Result<u64, String> {
        match HeaderClient::header_network_head(&self.client).await {
            Ok(extended_header) => Ok(extended_header.header.height.value()),
            Err(err) => Err(format!("Could not get network head from DA layer: {}", err)),
        }
    }

    async fn get(&self, height: u64) -> Result<Vec<EpochJson>, String> {
        debug! {"Getting epoch {} from DA layer", height};
        match BlobClient::blob_get_all(&self.client, height, &[self.namespace_id]).await {
            Ok(blobs) => {
                let mut epochs = Vec::new();
                for blob in blobs.iter() {
                    match EpochJson::try_from(blob) {
                        Ok(epoch_json) => epochs.push(epoch_json),
                        Err(_) => {
                            debug!("Could not parse epoch json for blob at height {}", height)
                        }
                    }
                }
                Ok(epochs)
            }
            Err(err) => Err(format!(
                "Could not get height {} from DA layer: {}",
                height, err
            )),
        }
    }

    async fn submit(&self, epoch: &EpochJson) -> Result<u64, String> {
        debug! {"Posting epoch {} to DA layer", epoch.height};
        // todo: unwraps (#11)
        let data = serde_json::to_string(&epoch).unwrap();
        let blob = Blob::new(self.namespace_id.clone(), data.into_bytes()).unwrap();
        debug!("blob: {}", serde_json::to_string(&blob).unwrap());
        match BlobClient::blob_submit(&self.client, &[blob]).await {
            Ok(height) => {
                debug!(
                    "Submitted epoch {} to DA layer at height {}",
                    epoch.height, height
                );
                Ok(height)
            }
            // TODO implement retries (#10)
            Err(err) => Err(format!("Could not submit epoch to DA layer: {}", err)),
        }
    }

    async fn start(&self) -> Result<(), String> {
        let mut header_sub = HeaderClient::header_subscribe(&self.client).await.unwrap();

        let tx1 = self.tx.clone();
        spawn(async move {
            while let Some(extended_header) = header_sub.next().await {
                let height = extended_header.unwrap().header.height.value();
                match tx1.send(Message::UpdateTarget(height)).await {
                    Ok(_) => {
                        debug!("Sent message to channel. Height: {}", height);
                    }
                    Err(_) => {
                        debug!("Could not send message to channel");
                    }
                }
            }
        });
        Ok(())
    }
}
