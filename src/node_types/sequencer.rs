use crate::{
    consts::{CHANNEL_BUFFER_SIZE, DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    error::{DataAvailabilityError, DatabaseError, DeimosResult},
};
use async_trait::async_trait;
use crypto_hash::{hex_digest, Algorithm};
use ed25519_dalek::{Signer, SigningKey};
use indexed_merkle_tree::{node::Node, tree::IndexedMerkleTree};
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
    storage::{ChainEntry, Database, IncomingEntry, Operation, UpdateEntryJson},
    utils::verify_signature,
    webserver::WebServer,
    zk_snark::{serialize_proof, serialize_verifying_key_to_custom, BatchMerkleProofCircuit},
};

pub struct Sequencer {
    pub db: Arc<dyn Database>,
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub epoch_duration: u64,
    pub ws: WebServer,
    pub key: SigningKey,

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
                if keys.len() == 0 {
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

        self.clone().main_loop().await;
        self.clone().da_loop().await;
        self.clone()
            .ws
            .start(self.clone())
            .await
            .map_err(|_| GeneralError::WebserverError.into())
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
            epoch_buffer_tx: Arc::new(tx),
            epoch_buffer_rx: Arc::new(Mutex::new(rx)),
        })
    }

    // main_loop is responsible for finalizing epochs every epoch length and writing them to the buffer for DA submission.
    async fn main_loop(self: Arc<Self>) {
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
        });
    }

    // da_loop is responsible for submitting finalized epochs to the DA layer.
    async fn da_loop(self: Arc<Self>) {
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
                                panic!(
                                    "da_loop: celestia account not funded, causing: {}",
                                    e.to_string()
                                );
                            }
                            error!("da_loop: submitting epoch: {}", e);
                            retry_counter += 1;
                            ticker.tick().await;
                        }
                    };
                }
            }
        });
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

        self.db.set_epoch(&epoch).map_err(DeimosError::Database)?;
        self.db
            .reset_epoch_operation_counter()
            .map_err(DeimosError::Database)?;

        // add the commitment for the operations ran since the last epoch
        let current_commitment = self
            .create_tree()?
            .get_commitment()
            .map_err(DeimosError::MerkleTree)?;

        self.db
            .add_commitment(&epoch, &current_commitment)
            .map_err(DeimosError::Database)?;

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
                Ok(commitment) => commitment,
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
            proof: serialize_proof(&proof),
            verifying_key: serialize_verifying_key_to_custom(&verifying_key),
            signature: None,
        };

        let serialized_epoch_json_without_signature =
            serde_json::to_string(&epoch_json).map_err(|e| {
                GeneralError::ParsingError(format!("epoch json: {}", e.to_string()).into())
            })?;
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
        // TODO: better error handling (#11)
        // Retrieve the keys from input order and sort them.
        let ordered_derived_dict_keys: Vec<String> =
            self.db.get_derived_keys_in_order().unwrap_or(vec![]);
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
                Ok(Node::new_leaf(
                    true,
                    true,
                    key.clone(),
                    value,
                    Node::TAIL.to_string(),
                ))
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

                match &mut nodes[i] {
                    Node::Leaf(leaf) => {
                        leaf.next = next_label;
                    }
                    _ => (),
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

            match ordered_derived_dict_keys
                .iter()
                .enumerate() // use index
                .find(|(_, k)| {
                    // without dereferencing we compare &&string with &string
                    label.clone().is_some_and(|l| *k == &l)
                }) {
                Some((k, _)) => Some(k),
                None => None,
            }
        });

        // Add empty nodes to ensure the total number of nodes is a power of two.
        while nodes.len() < next_power_of_two {
            nodes.push(Node::new_leaf(
                false,
                true,
                Node::EMPTY_HASH.to_string(),
                Node::EMPTY_HASH.to_string(),
                Node::TAIL.to_string(),
            ));
        }

        // create tree, setting left / right child property for each node
        IndexedMerkleTree::new(nodes).map_err(DeimosError::MerkleTree)
    }

    /// Updates an entry in the database based on the given operation, incoming entry, and the signature from the user.
    ///
    /// # Arguments
    ///
    /// * `operation` - An `Operation` enum variant representing the type of operation to be performed (Add or Revoke).
    /// * `incoming_entry` - A reference to an `IncomingEntry` struct containing the key and the entry data to be updated.
    /// * `signature` - A `Signature` struct representing the signature.
    pub fn update_entry(&self, signature: &UpdateEntryJson) -> DeimosResult<()> {
        debug!(
            "updating entry for uid {} with msg {}",
            signature.id, signature.signed_message
        );
        let signed_content = match verify_signature(signature, Some(signature.public_key.clone())) {
            Ok(content) => content,
            Err(_) => {
                // TODO(@distractedm1nd): Add to error instead of logging
                error!(
                    "updating entry for uid {}: invalid signature with pubkey {} on msg {}",
                    signature.id, signature.public_key, signature.signed_message
                );
                return Err(GeneralError::InvalidSignature.into());
            }
        };

        let message_obj: IncomingEntry = match serde_json::from_str(&signed_content) {
            Ok(obj) => obj,
            Err(e) => {
                return Err(GeneralError::ParsingError(format!(
                    "signed content: {}",
                    e.to_string()
                ))
                .into());
            }
        };

        // check with given key if the signature is valid
        let incoming_entry = IncomingEntry {
            id: signature.id.clone(),
            operation: message_obj.operation,
            value: message_obj.value,
        };
        // add a new key to an existing id  ( type for the value retrieved from the database explicitly set to string)
        match self.db.get_hashchain(&signature.id) {
            Ok(value) => {
                // hashchain already exists
                let mut current_chain = value.clone();
                let last = match current_chain.last() {
                    Some(entry) => entry,
                    None => {
                        return Err(DatabaseError::NotFoundError(format!(
                            "last value in hashchain for incoming entry with id {}",
                            signature.id.clone()
                        ))
                        .into());
                    }
                };

                let new_chain_entry = ChainEntry {
                    hash: hex_digest(
                        Algorithm::SHA256,
                        format!(
                            "{}, {}, {}",
                            &incoming_entry.operation, &incoming_entry.value, &last.hash
                        )
                        .as_bytes(),
                    ),
                    previous_hash: last.hash.clone(),
                    operation: incoming_entry.operation.clone(),
                    value: incoming_entry.value.clone(),
                };

                current_chain.push(new_chain_entry.clone());
                match self.db.update_hashchain(&incoming_entry, &current_chain) {
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
                    .set_derived_entry(&incoming_entry, &new_chain_entry, false)
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

                Ok(())
            }
            Err(_) => {
                debug!("Hashchain does not exist, creating new one...");
                let new_chain = vec![ChainEntry {
                    hash: hex_digest(
                        Algorithm::SHA256,
                        format!(
                            "{}, {}, {}",
                            Operation::Add,
                            &incoming_entry.value,
                            Node::EMPTY_HASH.to_string()
                        )
                        .as_bytes(),
                    ),
                    previous_hash: Node::EMPTY_HASH.to_string(),
                    operation: incoming_entry.operation.clone(),
                    value: incoming_entry.value.clone(),
                }];
                let last_entry = match new_chain.last() {
                    Some(entry) => entry,
                    None => {
                        return Err(DatabaseError::ReadError(format!(
                            "last value in hashchain for incoming entry with id {}",
                            signature.id.clone()
                        ))
                        .into());
                    }
                };
                match self.db.update_hashchain(&incoming_entry, &new_chain) {
                    Ok(_) => (),
                    Err(_) => {
                        return Err(DatabaseError::WriteError(format!(
                            "hashchain for incoming entry {:?}",
                            incoming_entry
                        ))
                        .into());
                    }
                }
                match self.db.set_derived_entry(&incoming_entry, last_entry, true) {
                    Ok(_) => Ok(()),
                    Err(_) => {
                        return Err(DatabaseError::WriteError(format!(
                            "derived entry for incoming entry {:?}",
                            incoming_entry
                        ))
                        .into());
                    }
                }
            }
        }
    }
}
