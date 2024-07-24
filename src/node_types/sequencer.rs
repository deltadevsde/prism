use crate::{
    consts::{CHANNEL_BUFFER_SIZE, DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    error::{DataAvailabilityError, DatabaseError, PrismResult},
};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use indexed_merkle_tree::{
    node::Node,
    sha256_mod,
    tree::{IndexedMerkleTree, Proof},
    Hash,
};
use std::{self, sync::Arc, time::Duration};
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::spawn,
    time::interval,
};

use crate::{
    cfg::Config,
    da::{DataAvailabilityLayer, EpochJson},
    error::{GeneralError, PrismError},
    node_types::NodeType,
    storage::{ChainEntry, Database, IncomingEntry, Operation},
    utils::verify_signature,
    webserver::{UpdateEntryJson, WebServer},
    zk_snark::BatchMerkleProofCircuit,
};

pub struct Sequencer {
    pub db: Arc<dyn Database>,
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub epoch_duration: u64,
    pub ws: WebServer,
    pub key: SigningKey,

    pending_entries: Arc<Mutex<Vec<IncomingEntry>>>,
    tree: Arc<Mutex<IndexedMerkleTree>>,

    epoch_buffer_tx: Arc<Sender<EpochJson>>,
    epoch_buffer_rx: Arc<Mutex<Receiver<EpochJson>>>,
}

#[async_trait]
impl NodeType for Sequencer {
    async fn start(self: Arc<Self>) -> PrismResult<()> {
        // start listening for new headers to update sync target
        if let Err(e) = self.da.start().await {
            return Err(DataAvailabilityError::InitializationError(e.to_string()).into());
        }

        let derived_keys = self.db.get_derived_keys();
        match derived_keys {
            Ok(keys) => {
                if keys.is_empty() {
                    // if the dict is empty, we need to initialize the dict and the input order
                    match self.db.initialize_derived_dict() {
                        Ok(_) => (),
                        Err(e) => {
                            error!("sequencer_loop: initializing derived dictionary: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("sequencer_loop: getting derived keys: {}", e);
            }
        }

        let main_loop = self.clone().main_loop();
        let da_loop = self.clone().da_loop();

        let ws_self = self.clone();
        let ws = ws_self.ws.start(self.clone());

        tokio::select! {
            _ = main_loop => Ok(()),
            _ = da_loop => Ok(()),
            _ = ws => Ok(()),
        }
    }
}

impl Sequencer {
    pub fn new(
        db: Arc<dyn Database>,
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: Config,
        key: SigningKey,
    ) -> PrismResult<Sequencer> {
        let (tx, rx) = channel(CHANNEL_BUFFER_SIZE);

        let epoch_duration = match cfg.epoch_time {
            Some(epoch_time) => epoch_time,
            None => {
                return Err(GeneralError::MissingArgumentError("epoch_time".to_string()).into());
            }
        };

        let ws = match cfg.webserver {
            Some(webserver) => WebServer::new(webserver),
            None => {
                return Err(
                    GeneralError::MissingArgumentError("webserver config".to_string()).into(),
                );
            }
        };

        Ok(Sequencer {
            db,
            da,
            epoch_duration,
            ws,
            key,
            tree: Arc::new(Mutex::new(IndexedMerkleTree::new_with_size(1024).unwrap())),
            pending_entries: Arc::new(Mutex::new(Vec::new())),
            epoch_buffer_tx: Arc::new(tx),
            epoch_buffer_rx: Arc::new(Mutex::new(rx)),
        })
    }

    // main_loop is responsible for finalizing epochs every epoch length and writing them to the buffer for DA submission.
    async fn main_loop(self: Arc<Self>) -> Result<(), tokio::task::JoinError> {
        info!("starting main sequencer loop");
        let epoch_buffer = self.epoch_buffer_tx.clone();
        let mut ticker = interval(Duration::from_secs(self.epoch_duration));
        spawn(async move {
            loop {
                ticker.tick().await;
                match self.finalize_epoch().await {
                    Ok(epoch) => {
                        let epoch_height = match self.db.get_epoch() {
                            Ok(epoch) => epoch,
                            Err(e) => {
                                error!("sequencer_loop: getting epoch from db: {}", e);
                                continue;
                            }
                        };

                        info!("sequencer_loop: finalized epoch {}", epoch_height);
                        match epoch_buffer.send(epoch).await {
                            Ok(_) => (),
                            Err(e) => {
                                error!("sequencer_loop: sending epoch to buffer: {}", e);
                            }
                        }
                    }
                    Err(e) => error!("sequencer_loop: finalizing epoch: {}", e),
                }
            }
        })
        .await
    }

    // da_loop is responsible for submitting finalized epochs to the DA layer.
    async fn da_loop(self: Arc<Self>) -> Result<(), tokio::task::JoinError> {
        info!("starting da submission loop");
        let mut ticker = interval(DA_RETRY_INTERVAL);
        spawn(async move {
            loop {
                let epoch = match self.get_latest_height().await {
                    Ok(e) => e,
                    Err(e) => {
                        error!("da_loop: getting latest height: {}", e);
                        continue;
                    }
                };
                let mut retry_counter = 0;
                loop {
                    if retry_counter > DA_RETRY_COUNT {
                        // todo: graceful shutdown
                        panic!("da_loop: too many retries, giving up");
                    }
                    match self.da.submit(&epoch).await {
                        Ok(height) => {
                            info!("da_loop: submitted epoch at height {}", height);
                            break;
                        }
                        Err(e) => {
                            // code = NotFound means the account is not funded
                            if e.to_string().contains("rpc error: code = NotFound") {
                                panic!("da_loop: celestia account not funded, causing: {}", e);
                            }
                            error!("da_loop: submitting epoch: {}", e);
                            retry_counter += 1;
                            ticker.tick().await;
                        }
                    };
                }
            }
        })
        .await
    }

    pub async fn get_commitment(&self) -> PrismResult<Hash> {
        let tree = self.tree.lock().await;
        tree.get_commitment().map_err(|e| e.into())
    }

    // finalize_epoch is responsible for finalizing the pending epoch and returning the epoch json to be posted on the DA layer.
    pub async fn finalize_epoch(&self) -> PrismResult<EpochJson> {
        let epoch = match self.db.get_epoch() {
            Ok(epoch) => epoch + 1,
            Err(_) => 0,
        };

        let prev_commitment = if epoch > 0 {
            let prev_epoch = epoch - 1;
            match self.db.get_commitment(&prev_epoch) {
                Ok(commitment) => Hash::from_hex(commitment.as_str()).unwrap(),
                Err(e) => {
                    return Err(DatabaseError::ReadError(format!(
                        "commitment for prev epoch {:?}: {:?}",
                        prev_epoch,
                        e.to_string()
                    ))
                    .into());
                }
            }
        } else {
            self.get_commitment().await?
        };

        let proofs = self.finalize_pending_entries().await?;

        let current_commitment = {
            let tree = self.tree.lock().await;
            tree.get_commitment().map_err(PrismError::MerkleTree)?
        };

        self.db.set_epoch(&epoch)?;
        // add the commitment for the operations ran since the last epoch
        self.db.add_commitment(&epoch, &current_commitment)?;

        let batch_circuit =
            BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs)?;
        let (proof, verifying_key) = batch_circuit.create_and_verify_snark()?;

        let epoch_json = EpochJson {
            height: epoch,
            prev_commitment,
            current_commitment,
            proof: proof.into(),
            verifying_key: verifying_key.into(),
            signature: None,
        };

        let serialized_epoch_json_without_signature = serde_json::to_string(&epoch_json)
            .map_err(|e| GeneralError::ParsingError(format!("epoch json: {}", e)))?;
        let signature = self
            .key
            .sign(serialized_epoch_json_without_signature.as_bytes())
            .to_string();
        let mut epoch_json_with_signature = epoch_json;
        epoch_json_with_signature.signature = Some(signature.clone());
        Ok(epoch_json_with_signature)
    }

    async fn get_latest_height(&self) -> PrismResult<EpochJson> {
        match self.epoch_buffer_rx.lock().await.recv().await {
            Some(epoch) => Ok(epoch),
            None => Err(DataAvailabilityError::ChannelReceiveError.into()),
        }
    }

    async fn finalize_pending_entries(&self) -> PrismResult<Vec<Proof>> {
        let mut pending_entries = self.pending_entries.lock().await;
        let mut proofs = Vec::new();
        for entry in pending_entries.iter() {
            let proof = self.update_entry(entry).await?;
            proofs.push(proof);
        }
        pending_entries.clear();
        Ok(proofs)
    }

    /// Updates the state from on a pending incoming entry.
    async fn update_entry(&self, incoming_entry: &IncomingEntry) -> PrismResult<Proof> {
        let id = incoming_entry.id.clone();
        // add a new key to an existing id  ( type for the value retrieved from the database explicitly set to string)
        let hashchain: PrismResult<Vec<ChainEntry>> = match self.db.get_hashchain(&id) {
            Ok(value) => {
                // hashchain already exists
                let mut current_chain = value.clone();
                let last = match current_chain.last() {
                    Some(entry) => entry,
                    None => {
                        return Err(DatabaseError::NotFoundError(format!(
                            "last value in hashchain for incoming entry with id {}",
                            id.clone()
                        ))
                        .into());
                    }
                };

                let new_chain_entry = ChainEntry {
                    hash: {
                        let mut data = Vec::new();
                        data.extend_from_slice(incoming_entry.operation.to_string().as_bytes());
                        data.extend_from_slice(incoming_entry.value.as_ref());
                        data.extend_from_slice(last.hash.as_ref());
                        sha256_mod(&data)
                    },
                    previous_hash: last.hash,
                    operation: incoming_entry.operation.clone(),
                    value: sha256_mod(incoming_entry.value.as_bytes()),
                };

                current_chain.push(new_chain_entry.clone());
                match self.db.update_hashchain(incoming_entry, &current_chain) {
                    Ok(_) => (),
                    Err(_) => {
                        return Err(DatabaseError::WriteError(format!(
                            "hashchain for incoming entry {:?}",
                            incoming_entry
                        ))
                        .into());
                    }
                }
                match self
                    .db
                    .set_derived_entry(incoming_entry, &new_chain_entry, false)
                {
                    Ok(_) => (),
                    Err(_) => {
                        return Err(DatabaseError::WriteError(format!(
                            "derived entry for incoming entry {:?}",
                            incoming_entry
                        ))
                        .into());
                    }
                }

                Ok(value)
            }
            Err(e) => {
                debug!("creating new hashchain for user id {}", id.clone());
                let new_chain = vec![ChainEntry {
                    hash: {
                        let mut data = Vec::new();
                        data.extend_from_slice(Operation::Add.to_string().as_bytes());
                        data.extend_from_slice(incoming_entry.value.as_ref());
                        data.extend_from_slice(Node::HEAD.as_ref());
                        sha256_mod(&data)
                    },
                    previous_hash: Node::HEAD,
                    operation: incoming_entry.operation.clone(),
                    value: sha256_mod(incoming_entry.value.as_bytes()),
                }];
                let last_entry = match new_chain.last() {
                    Some(entry) => entry,
                    None => {
                        return Err(DatabaseError::ReadError(format!(
                            "last value in hashchain for incoming entry with id {}",
                            id.clone()
                        ))
                        .into());
                    }
                };
                match self.db.update_hashchain(incoming_entry, &new_chain) {
                    Ok(_) => (),
                    Err(_) => {
                        return Err(DatabaseError::WriteError(format!(
                            "hashchain for incoming entry {:?}",
                            incoming_entry
                        ))
                        .into());
                    }
                }
                match self.db.set_derived_entry(incoming_entry, last_entry, true) {
                    // we return the error so that the node is updated rather than inserted
                    Ok(_) => Err(e),
                    Err(_) => Err(DatabaseError::WriteError(format!(
                        "derived entry for incoming entry {:?}",
                        incoming_entry
                    ))
                    .into()),
                }
            }
        };

        let mut tree = self.tree.lock().await;
        let hashed_id = sha256_mod(id.as_bytes());

        // todo: not all error cases make it okay to continue here, so we should filter by a Hashchain key not found error
        if hashchain.is_ok() {
            let node = match tree.find_leaf_by_label(&hashed_id) {
                Some(node) => node,
                None => {
                    // TODO: before merging, change error type
                    return Err(GeneralError::DecodingError(format!(
                        "node with label {} not found in the tree",
                        hashed_id
                    ))
                    .into());
                }
            };
            let new_index = match tree.find_node_index(&node) {
                Some(index) => index,
                None => {
                    return Err(GeneralError::DecodingError(format!(
                        "node with label {} not found in the tree, but has a hashchain entry",
                        hashed_id
                    ))
                    .into());
                }
            };
            // TODO: Possible optimization: cache the last update proof for each id for serving the proofs
            tree.update_node(new_index, node)
                .map(Proof::Update)
                .map_err(|e| e.into())
        } else {
            let mut node = Node::new_leaf(
                true,
                hashed_id,
                sha256_mod(incoming_entry.value.as_bytes()),
                sha256_mod("PLACEHOLDER".as_bytes()),
            );
            tree.insert_node(&mut node)
                .map(Proof::Insert)
                .map_err(|e| e.into())
        }
    }

    /// Adds an update to be applied in the next epoch.
    ///
    /// # Arguments
    ///
    /// * `signed_entry` - A `UpdateEntryJson` object.
    pub async fn validate_and_queue_update(
        self: Arc<Self>,
        signed_entry: &UpdateEntryJson,
    ) -> PrismResult<()> {
        let signed_content = match verify_signature(signed_entry, None) {
            Ok(content) => content,
            Err(e) => {
                // TODO(@distractedm1nd): Add to error instead of logging
                error!(
                    "updating entry: invalid signature with pubkey {} on msg {}",
                    signed_entry.public_key, signed_entry.signed_incoming_entry
                );
                return Err(e);
            }
        };

        let incoming: IncomingEntry = match serde_json::from_str(&signed_content) {
            Ok(obj) => obj,
            Err(e) => {
                return Err(GeneralError::ParsingError(format!("signed content: {}", e)).into());
            }
        };

        let mut pending = self.pending_entries.lock().await;
        pending.push(incoming);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cfg::{Config, RedisConfig},
        da::mock::LocalDataAvailabilityLayer,
        storage::RedisConnection,
    };
    use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
    use keystore_rs::create_signing_key;
    use serial_test::serial;

    // set up redis connection and flush database before each test
    fn setup_db() -> RedisConnection {
        let redis_connection = RedisConnection::new(&RedisConfig::default()).unwrap();
        redis_connection.flush_database().unwrap();
        redis_connection
    }

    // flush database after each test
    fn teardown_db(redis_connections: &RedisConnection) {
        redis_connections.flush_database().unwrap();
    }

    fn create_update_entry(id: String, value: String) -> UpdateEntryJson {
        let key = create_signing_key();
        let incoming = IncomingEntry {
            id,
            operation: Operation::Add,
            value,
        };
        let content = serde_json::to_string(&incoming).unwrap();
        let sig = key.sign(content.clone().as_bytes());

        UpdateEntryJson {
            incoming_entry: incoming,
            signed_incoming_entry: sig.to_string(),
            public_key: engine.encode(key.verifying_key().to_bytes()),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_validate_and_queue_update() {
        let da_layer = Arc::new(LocalDataAvailabilityLayer::new());
        let db = Arc::new(setup_db());
        let sequencer = Arc::new(
            Sequencer::new(
                db.clone(),
                da_layer,
                Config::default(),
                create_signing_key(),
            )
            .unwrap(),
        );

        let update_entry =
            create_update_entry("test@deltadevs.xyz".to_string(), "test".to_string());

        sequencer
            .validate_and_queue_update(&update_entry)
            .await
            .unwrap();
        teardown_db(&db);
    }

    #[tokio::test]
    #[serial]
    async fn test_queued_update_gets_finalized() {
        let da_layer = Arc::new(LocalDataAvailabilityLayer::new());
        let db = Arc::new(setup_db());
        let sequencer = Arc::new(
            Sequencer::new(
                db.clone(),
                da_layer,
                Config::default(),
                create_signing_key(),
            )
            .unwrap(),
        );

        let id = "test@deltadevs.xyz".to_string();
        let update_entry = create_update_entry(id.clone(), "test".to_string());

        sequencer
            .clone()
            .validate_and_queue_update(&update_entry)
            .await
            .unwrap();

        // hashchain doesn't exist yet, because operation is only queued
        let hashchain = sequencer.db.get_hashchain(id.as_str());
        assert!(hashchain.is_err());

        let prev_commitment = sequencer.get_commitment().await.unwrap();
        sequencer.finalize_epoch().await.unwrap();
        let new_commitment = sequencer.get_commitment().await.unwrap();
        assert_ne!(prev_commitment, new_commitment);

        let hashchain = sequencer.db.get_hashchain(id.as_str());
        assert_eq!(
            hashchain.unwrap().first().unwrap().value,
            sha256_mod("test".as_bytes())
        );

        teardown_db(&db);
    }

    #[tokio::test]
    #[serial]
    async fn test_validate_invalid_update_fails() {
        let da_layer = Arc::new(LocalDataAvailabilityLayer::new());
        let db = Arc::new(setup_db());
        let sequencer = Arc::new(
            Sequencer::new(
                db.clone(),
                da_layer,
                Config::default(),
                create_signing_key(),
            )
            .unwrap(),
        );

        let mut update_entry =
            create_update_entry("test@deltadevs.xyz".to_string(), "test".to_string());
        let second_signer = create_update_entry("abcd".to_string(), "test".to_string()).public_key;
        update_entry.public_key = second_signer;

        let res = sequencer.validate_and_queue_update(&update_entry).await;
        assert!(res.is_err());
        teardown_db(&db);
    }
}
