use async_trait::async_trait;
use ed25519::Signature;
use ed25519_dalek::{Signer, SigningKey};
use indexed_merkle_tree::{
    node::Node,
    sha256_mod,
    tree::{IndexedMerkleTree, Proof},
    Hash,
};
use std::{self, str::FromStr, sync::Arc, time::Duration};
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
    common::{AccountSource, HashchainEntry, Operation},
    consts::{CHANNEL_BUFFER_SIZE, DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    da::{DataAvailabilityLayer, FinalizedEpoch},
    error::GeneralError,
    error::{DataAvailabilityError, DatabaseError, PrismError, PrismResult},
    node_types::NodeType,
    storage::Database,
    webserver::{OperationInput, WebServer},
    zk_snark::BatchMerkleProofCircuit,
};

pub struct Sequencer {
    pub db: Arc<dyn Database>,
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub epoch_duration: u64,
    pub ws: WebServer,
    pub key: SigningKey,

    pending_entries: Arc<Mutex<Vec<Operation>>>,
    tree: Arc<Mutex<IndexedMerkleTree>>,

    epoch_buffer_tx: Arc<Sender<FinalizedEpoch>>,
    epoch_buffer_rx: Arc<Mutex<Receiver<FinalizedEpoch>>>,
}

#[async_trait]
impl NodeType for Sequencer {
    async fn start(self: Arc<Self>) -> PrismResult<()> {
        if let Err(e) = self.da.start().await {
            return Err(DataAvailabilityError::InitializationError(e.to_string()).into());
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
                let epoch = match self.receive_finalized_epoch().await {
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
                    match self.da.submit_snarks(vec![epoch.clone()]).await {
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

    // finalize_epoch is responsible for finalizing the pending epoch and returning the [`FinalizedEpoch`] to be posted on the DA layer.
    pub async fn finalize_epoch(&self) -> PrismResult<FinalizedEpoch> {
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

        let epoch_json = FinalizedEpoch {
            height: epoch,
            prev_commitment,
            current_commitment,
            proof: proof.into(),
            verifying_key: verifying_key.into(),
            signature: None,
        };

        let serialized_epoch_json_without_signature = borsh::to_vec(&epoch_json)
            .map_err(|e| GeneralError::ParsingError(format!("epoch: {}", e)))?;
        let signature = self
            .key
            .sign(serialized_epoch_json_without_signature.as_slice())
            .to_string();
        let mut epoch_json_with_signature = epoch_json;
        epoch_json_with_signature.signature = Some(signature.clone());
        Ok(epoch_json_with_signature)
    }

    async fn receive_finalized_epoch(&self) -> PrismResult<FinalizedEpoch> {
        match self.epoch_buffer_rx.lock().await.recv().await {
            Some(epoch) => Ok(epoch),
            None => Err(DataAvailabilityError::ChannelReceiveError.into()),
        }
    }

    // finalize_pending_entries processes all pending entries and returns the proofs.
    async fn finalize_pending_entries(&self) -> PrismResult<Vec<Proof>> {
        let mut pending_entries = self.pending_entries.lock().await;
        let mut proofs = Vec::new();
        for entry in pending_entries.iter() {
            let proof = self.process_operation(entry).await?;
            proofs.push(proof);
        }
        pending_entries.clear();
        Ok(proofs)
    }

    /// Updates the state from an already verified pending operation.
    async fn process_operation(&self, operation: &Operation) -> PrismResult<Proof> {
        match operation {
            Operation::Add { id, .. } | Operation::Revoke { id, .. } => {
                // verify that the hashchain already exists
                let mut current_chain = self.db.get_hashchain(id).map_err(|e| {
                    DatabaseError::NotFoundError(format!("hashchain for ID {}: {}", id, e))
                })?;

                let mut tree = self.tree.lock().await;
                let hashed_id = sha256_mod(id.as_bytes());

                let node = tree.find_leaf_by_label(&hashed_id).ok_or_else(|| {
                    // TODO: Change error type in anyhow error PR
                    GeneralError::DecodingError(format!(
                        "node with label {} not found in the tree",
                        hashed_id
                    ))
                })?;

                let previous_hash = current_chain.last().unwrap().hash;

                let new_chain_entry = HashchainEntry::new(operation.clone(), previous_hash);
                current_chain.push(new_chain_entry.clone());

                let updated_node = Node::new_leaf(
                    node.is_left_sibling(),
                    hashed_id,
                    new_chain_entry.hash,
                    node.get_next(),
                );

                let index = tree.find_node_index(&node).ok_or_else(|| {
                    GeneralError::DecodingError(format!(
                        "node with label {} not found in the tree, but has a hashchain entry",
                        hashed_id
                    ))
                })?;

                self.db
                    .update_hashchain(operation, &current_chain)
                    .map_err(|e| {
                        PrismError::Database(DatabaseError::WriteError(format!(
                            "hashchain for incoming operation {:?}: {:?}",
                            operation, e
                        )))
                    })?;

                tree.update_node(index, updated_node)
                    .map(Proof::Update)
                    .map_err(|e| e.into())
            }
            Operation::CreateAccount { id, value, source } => {
                // validation of account source
                match source {
                    // TODO: use Signature, not String
                    AccountSource::SignedBySequencer { signature } => {
                        let sig = Signature::from_str(signature).map_err(|_| {
                            PrismError::General(GeneralError::ParsingError(
                                "sequencer's signature on operation".to_string(),
                            ))
                        })?;
                        self.key
                            .verify(format!("{}{}", id, value).as_bytes(), &sig)
                            .map_err(|e| PrismError::General(GeneralError::InvalidSignature(e)))
                    }
                }?;

                let hashchain: PrismResult<Vec<HashchainEntry>> = self.db.get_hashchain(id);
                if hashchain.is_ok() {
                    return Err(DatabaseError::NotFoundError(format!(
                        "empty slot for ID {}",
                        id.clone()
                    ))
                    .into());
                }

                debug!("creating new hashchain for user id {}", id.clone());
                let new_chain = vec![HashchainEntry::new(operation.clone(), Node::HEAD)];

                self.db
                    .update_hashchain(operation, &new_chain)
                    .map_err(|e| {
                        PrismError::Database(DatabaseError::WriteError(format!(
                            "hashchain for incoming operation {:?}: {:?}",
                            operation, e
                        )))
                    })?;

                let mut tree = self.tree.lock().await;
                let hashed_id = sha256_mod(id.as_bytes());

                let mut node =
                    Node::new_leaf(true, hashed_id, new_chain.first().unwrap().hash, Node::TAIL);
                tree.insert_node(&mut node)
                    .map(Proof::Insert)
                    .map_err(|e| e.into())
            }
        }
    }

    /// Adds an operation to be posted to the DA layer and applied in the next epoch.
    pub async fn validate_and_queue_update(
        self: Arc<Self>,
        incoming_operation: &OperationInput,
    ) -> PrismResult<()> {
        // TODO: this is only basic validation. The validation over if an entry can be added to the hashchain or not is done in the process_operation function
        incoming_operation.validate()?;
        let mut pending = self.pending_entries.lock().await;
        pending.push(incoming_operation.operation.clone());
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

    fn create_new_entry(id: String, value: String, key: SigningKey) -> OperationInput {
        let incoming = Operation::CreateAccount {
            id: id.clone(),
            value: value.clone(),
            source: AccountSource::SignedBySequencer {
                signature: key.sign(format!("{}{}", id, value).as_bytes()).to_string(),
            },
        };
        let content = serde_json::to_string(&incoming).unwrap();
        let sig = key.sign(content.clone().as_bytes());

        OperationInput {
            operation: incoming,
            signed_operation: sig.to_string(),
            public_key: engine.encode(key.verifying_key().to_bytes()),
        }
    }

    fn create_update_entry(id: String, value: String) -> OperationInput {
        let key = create_signing_key();
        let incoming = Operation::Add { id, value };
        let content = serde_json::to_string(&incoming).unwrap();
        let sig = key.sign(content.clone().as_bytes());

        OperationInput {
            operation: incoming,
            signed_operation: sig.to_string(),
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
        let signing_key = create_signing_key();
        let sequencer = Arc::new(
            Sequencer::new(db.clone(), da_layer, Config::default(), signing_key.clone()).unwrap(),
        );

        let id = "test@deltadevs.xyz".to_string();
        let update_entry = create_new_entry(id.clone(), "test".to_string(), signing_key.clone());

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
        let value = hashchain.unwrap().first().unwrap().operation.value();
        assert_eq!(value, "test");

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
