use crate::{
    consts::{CHANNEL_BUFFER_SIZE, DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    error::{DataAvailabilityError, DatabaseError, DeimosResult},
};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use indexed_merkle_tree::{
    node::Node,
    sha256_mod,
    tree::{IndexedMerkleTree, MerkleProof, Proof},
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
    error::{DeimosError, GeneralError},
    node_types::NodeType,
    storage::{ChainEntry, Database, IncomingEntry, Operation},
    utils::verify_signature,
    webserver::UpdateEntryJson,
    webserver::WebServer,
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
    async fn start(self: Arc<Self>) -> DeimosResult<()> {
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
    ) -> DeimosResult<Sequencer> {
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

    /// Initializes the epoch state by setting up the input table and incrementing the epoch number.
    /// Periodically calls the `set_epoch_commitment` function to update the commitment for the current epoch.
    ///
    /// # Behavior
    /// 1. Initializes the input table by inserting an empty hash if it is empty.
    /// 2. Updates the epoch number in the app state.
    /// 3. Waits for a specified duration before starting the next epoch.
    /// 4. Calls `set_epoch_commitment` to fetch and set the commitment for the current epoch.
    /// 5. Repeats steps 2-4 periodically.
    pub async fn finalize_epoch(&self) -> DeimosResult<EpochJson> {
        let epoch = match self.db.get_epoch() {
            Ok(epoch) => epoch + 1,
            Err(_) => 0,
        };

        self.finalize_pending_entries().await?;
        self.db.set_epoch(&epoch)?;

        // add the commitment for the operations ran since the last epoch
        let tree = self.tree.lock().await;
        let current_commitment = tree.get_commitment().map_err(DeimosError::MerkleTree)?;

        self.db.add_commitment(&epoch, &current_commitment)?;

        let proofs = match epoch > 0 {
            true => match self.db.get_proofs_in_epoch(&(epoch - 1)) {
                Ok(proofs) => proofs,
                Err(e) => return Err(DatabaseError::ReadError(e.to_string()).into()),
            },
            false => vec![],
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
            let empty_commitment = self.create_tree()?;
            empty_commitment
                .get_commitment()
                .map_err(DeimosError::MerkleTree)?
        };

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

    async fn get_latest_height(&self) -> DeimosResult<EpochJson> {
        match self.epoch_buffer_rx.lock().await.recv().await {
            Some(epoch) => Ok(epoch),
            None => Err(DataAvailabilityError::ChannelReceiveError.into()),
        }
    }

    pub fn create_tree(&self) -> DeimosResult<IndexedMerkleTree> {
        // Retrieve the keys from input order and sort them.
        let ordered_derived_dict_keys: Vec<String> =
            self.db.get_derived_keys_in_order().unwrap_or_default();
        let mut sorted_keys = ordered_derived_dict_keys.clone();
        sorted_keys.sort();

        // Initialize the leaf nodes with the value corresponding to the given key. Set the next node to the tail for now.
        let nodes_result: Result<Vec<Node>, DatabaseError> = sorted_keys
            .iter()
            .map(|key| {
                let value: String = self
                    .db
                    .get_derived_value(&key.to_string())
                    .map_err(|e| DatabaseError::ReadError(e.to_string()))?;
                let hash_key = Hash::from_hex(key).unwrap();
                let hash_value = Hash::from_hex(&value).unwrap();
                Ok(Node::new_leaf(true, true, hash_key, hash_value, Node::TAIL))
            })
            .collect();

        let mut nodes: Vec<Node> = nodes_result?;

        // calculate the next power of two, tree size is at least 8 for now
        let mut next_power_of_two: usize = 8;
        while next_power_of_two < ordered_derived_dict_keys.len() + 1 {
            next_power_of_two *= 2;
        }

        // Calculate the node hashes and sort the keys (right now they are sorted, so the next node is always the one bigger than the current one)
        for i in 0..nodes.len() - 1 {
            let is_next_node_active = nodes[i + 1].is_active();
            if is_next_node_active {
                let next_label = match &nodes[i + 1] {
                    Node::Leaf(next_leaf) => next_leaf.label.clone(),
                    _ => unreachable!(),
                };

                if let Node::Leaf(leaf) = &mut nodes[i] {
                    leaf.next = next_label;
                }

                nodes[i].generate_hash();
            }
        }

        // resort the nodes based on the input order
        nodes.sort_by_cached_key(|node| {
            let label = match node {
                Node::Inner(_) => None,
                Node::Leaf(leaf) => {
                    let label = leaf.label.clone();
                    Some(label)
                }
            };

            ordered_derived_dict_keys
                .iter()
                .enumerate() // use index
                .find(|(_, k)| {
                    let k = Hash::from_hex(k).unwrap();
                    label.clone().is_some_and(|l| k == l)
                })
                .map(|(k, _)| k)
        });

        // Add empty nodes to ensure the total number of nodes is a power of two.
        while nodes.len() < next_power_of_two {
            nodes.push(Node::new_leaf(
                false,
                true,
                Node::HEAD,
                Node::HEAD,
                Node::TAIL,
            ));
        }

        // create tree, setting left / right child property for each node
        IndexedMerkleTree::new(nodes).map_err(DeimosError::MerkleTree)
    }

    async fn finalize_pending_entries(&self) -> DeimosResult<()> {
        let mut pending_entries = self.pending_entries.lock().await;
        for entry in pending_entries.iter() {
            self.update_entry(entry).await?;
        }
        pending_entries.clear();
        Ok(())
    }

    /// Updates the state from on a pending incoming entry.
    async fn update_entry(&self, incoming_entry: &IncomingEntry) -> DeimosResult<Proof> {
        let id = incoming_entry.id.clone();
        // add a new key to an existing id  ( type for the value retrieved from the database explicitly set to string)
        let hashchain: DeimosResult<Vec<ChainEntry>> = match self.db.get_hashchain(&id) {
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
                    previous_hash: last.hash.clone(),
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
        let mut node = match tree.find_leaf_by_label(&hashed_id) {
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

        // If the hashchain exists, its an Update
        if hashchain.is_ok() {
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
    ) -> DeimosResult<()> {
        let signed_content =
            match verify_signature(signed_entry, Some(signed_entry.public_key.clone())) {
                Ok(content) => content,
                Err(_) => {
                    // TODO(@distractedm1nd): Add to error instead of logging
                    error!(
                        "updating entry: invalid signature with pubkey {} on msg {}",
                        signed_entry.public_key, signed_entry.signed_incoming_entry
                    );
                    return Err(GeneralError::InvalidSignature.into());
                }
            };

        let incoming: IncomingEntry = match serde_json::from_str(&signed_content) {
            Ok(obj) => obj,
            Err(e) => {
                return Err(GeneralError::ParsingError(format!("signed content: {}", e)).into());
            }
        };

        let mut pending = self.pending_entries.lock().await;
        pending.push(incoming_entry);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{Config, RedisConfig};
    use crate::da::mock::LocalDataAvailabilityLayer;
    use crate::storage::RedisConnection;
    use keystore_rs::create_signing_key;

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

    // fn create_update_entry(id: String) -> UpdateEntryJson {
    //     let key = create_signing_key();
    //     let incoming = IncomingEntry {
    //         id,
    //         operation: Operation::Add,
    //         value: "test".to_string(),
    //     };
    //     let sig = key.sign(&serde_json::to_string(&incoming).unwrap().as_bytes());

    //     UpdateEntryJson {
    //         signed_incoming_entry: sig.to_bytes().to_string(),
    //         public_key: key.verifying_key().as_bytes().to_string(),
    //     }
    // }

    #[tokio::test]
    async fn test_update() {
        let da_layer = Arc::new(LocalDataAvailabilityLayer::new());
        let db = Arc::new(setup_db());
        let sequencer = Sequencer::new(
            db.clone(),
            da_layer,
            Config::default(),
            create_signing_key(),
        )
        .unwrap();

        // sequencer.validate_and_queue_update(&CUpdateEntryJson {
    }
}
