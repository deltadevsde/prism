use anyhow::{bail, ensure, Result};
use jmt::{
    storage::{TreeReader, TreeWriter},
    KeyHash,
};
use prism_errors::DatabaseError;
use prism_serde::binary::BinaryTranscodable;
use std::convert::Into;

use crate::{
    digest::Digest,
    hashchain::{Hashchain, HashchainEntry},
    hasher::Hasher,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput},
    transaction::Transaction,
    tree::{HashchainResponse::*, *},
};

/// Represents a tree that can be used to verifiably store and retrieve [`Hashchain`]s.
/// The methods of this trait are NOT run in circuit: they are used to create verifiable inputs for the circuit.
/// This distinction is critical because the returned proofs must contain all information necessary to verify the operations.
pub trait SnarkableTree: Send + Sync {
    fn process_transaction(&mut self, transaction: Transaction) -> Result<Proof>;
    fn insert(&mut self, key: KeyHash, entry: HashchainEntry) -> Result<InsertProof>;
    fn update(&mut self, key: KeyHash, entry: HashchainEntry) -> Result<UpdateProof>;
    fn get(&self, key: KeyHash) -> Result<HashchainResponse>;
}

impl<S> SnarkableTree for KeyDirectoryTree<S>
where
    S: Send + Sync + TreeReader + TreeWriter,
{
    fn process_transaction(&mut self, transaction: Transaction) -> Result<Proof> {
        match &transaction.entry.operation {
            Operation::AddKey { .. } | Operation::RevokeKey { .. } | Operation::AddData { .. } => {
                let hashed_id = Digest::hash(&transaction.id);
                let key_hash = KeyHash::with::<Hasher>(hashed_id);

                debug!("updating hashchain for user id {}", transaction.id);
                let proof = self.update(key_hash, transaction.entry)?;

                Ok(Proof::Update(Box::new(proof)))
            }
            Operation::CreateAccount {
                id,
                service_id,
                challenge,
                key,
            } => {
                ensure!(
                    transaction.id == id.as_str(),
                    "Id of transaction needs to be equal to operation id"
                );

                let hashed_id = Digest::hash(id);
                let account_key_hash = KeyHash::with::<Hasher>(hashed_id);

                // Verify that the account doesn't already exist
                if matches!(self.get(account_key_hash)?, Found(_, _)) {
                    bail!(DatabaseError::NotFoundError(format!(
                        "Account already exists for ID {}",
                        id
                    )));
                }

                let service_key_hash = KeyHash::with::<Hasher>(Digest::hash(service_id.as_bytes()));

                let Found(service_hashchain, _) = self.get(service_key_hash)? else {
                    bail!("Failed to get hashchain for service ID {}", service_id);
                };

                let Some(service_last_entry) = service_hashchain.last() else {
                    bail!("Service hashchain is empty, could not retrieve challenge key");
                };

                let creation_gate = match &service_last_entry.operation {
                    Operation::RegisterService { creation_gate, .. } => creation_gate,
                    _ => {
                        bail!("Service hashchain's last entry was not a RegisterService operation")
                    }
                };

                // Hash and sign credentials that have been signed by the external service
                let hash =
                    Digest::hash_items(&[id.as_bytes(), service_id.as_bytes(), &key.to_bytes()]);

                let ServiceChallenge::Signed(service_pubkey) = creation_gate;
                let ServiceChallengeInput::Signed(challenge_signature) = &challenge;

                service_pubkey.verify_signature(&hash.to_bytes(), challenge_signature)?;

                debug!("creating new hashchain for user ID {}", id);

                let insert_proof = self.insert(account_key_hash, transaction.entry)?;
                Ok(Proof::Insert(Box::new(insert_proof)))
            }
            Operation::RegisterService { id, .. } => {
                ensure!(
                    transaction.id == id.as_str(),
                    "Id of transaction needs to be equal to operation id"
                );

                let hashed_id = Digest::hash(id);
                let key_hash = KeyHash::with::<Hasher>(hashed_id);

                debug!("creating new hashchain for service id {}", id);

                let insert_proof = self.insert(key_hash, transaction.entry)?;
                Ok(Proof::Insert(Box::new(insert_proof)))
            }
        }
    }

    fn insert(&mut self, key: KeyHash, entry: HashchainEntry) -> Result<InsertProof> {
        let old_root = self.get_current_root()?;
        let (None, non_membership_merkle_proof) = self.jmt.get_with_proof(key, self.epoch)? else {
            bail!("Key already exists");
        };

        let non_membership_proof = NonMembershipProof {
            root: old_root.into(),
            proof: non_membership_merkle_proof,
            key,
        };

        let hashchain = Hashchain::from_entry(entry.clone())?;
        let serialized_hashchain = hashchain.encode_to_bytes()?;

        // the update proof just contains another nm proof
        let (new_root, _, tree_update_batch) = self
            .jmt
            .put_value_set_with_proof(vec![(key, Some(serialized_hashchain))], self.epoch + 1)?;
        self.queue_batch(tree_update_batch);
        self.write_batch()?;

        let (_, membership_proof) = self.jmt.get_with_proof(key, self.epoch)?;

        Ok(InsertProof {
            new_root: new_root.into(),
            new_entry: entry,
            non_membership_proof,
            membership_proof,
        })
    }

    fn update(&mut self, key: KeyHash, entry: HashchainEntry) -> Result<UpdateProof> {
        let old_root = self.get_current_root()?;
        let (Some(old_serialized_hashchain), inclusion_proof) =
            self.jmt.get_with_proof(key, self.epoch)?
        else {
            bail!("Key does not exist");
        };

        let old_hashchain = Hashchain::decode_from_bytes(&old_serialized_hashchain)?;

        let mut new_hashchain = old_hashchain.clone();
        new_hashchain.add_entry(entry.clone())?;

        let serialized_value = new_hashchain.encode_to_bytes()?;

        let (new_root, update_proof, tree_update_batch) = self.jmt.put_value_set_with_proof(
            vec![(key, Some(serialized_value.clone()))],
            self.epoch + 1,
        )?;
        self.queue_batch(tree_update_batch);
        self.write_batch()?;

        Ok(UpdateProof {
            old_root,
            new_root,
            inclusion_proof,
            old_hashchain,
            key,
            update_proof,
            new_entry: entry,
        })
    }

    fn get(&self, key: KeyHash) -> Result<HashchainResponse> {
        let root = self.get_current_root()?.into();
        let (value, proof) = self.jmt.get_with_proof(key, self.epoch)?;

        match value {
            Some(serialized_value) => {
                let deserialized_value = Hashchain::decode_from_bytes(&serialized_value)?;
                let membership_proof = MembershipProof {
                    root,
                    proof,
                    key,
                    value: deserialized_value.clone(),
                };
                Ok(Found(deserialized_value, membership_proof))
            }
            None => {
                let non_membership_proof = NonMembershipProof { root, proof, key };
                Ok(NotFound(non_membership_proof))
            }
        }
    }
}
