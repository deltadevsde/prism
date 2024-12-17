use anyhow::{bail, ensure, Result};
use jmt::{
    storage::{TreeReader, TreeWriter},
    KeyHash,
};
use log::debug;
use prism_errors::DatabaseError;
use prism_serde::{
    binary::{FromBinary, ToBinary},
    hex::ToHex,
};

use prism_common::{
    account::Account,
    digest::Digest,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput},
    transaction::Transaction,
};

use crate::{
    hasher::TreeHasher,
    key_directory_tree::KeyDirectoryTree,
    proofs::{InsertProof, MembershipProof, NonMembershipProof, Proof, UpdateProof},
    AccountResponse::{self, *},
};

/// Represents a tree that can be used to verifiably store and retrieve [`Account`]s.
/// The methods of this trait are NOT run in circuit: they are used to create verifiable inputs for the circuit.
/// This distinction is critical because the returned proofs must contain all information necessary to verify the operations.
pub trait SnarkableTree: Send + Sync {
    fn process_transaction(&mut self, transaction: Transaction) -> Result<Proof>;
    fn insert(&mut self, key: KeyHash, tx: Transaction) -> Result<InsertProof>;
    fn update(&mut self, key: KeyHash, tx: Transaction) -> Result<UpdateProof>;
    fn get(&self, key: KeyHash) -> Result<AccountResponse>;
}

impl<S> SnarkableTree for KeyDirectoryTree<S>
where
    S: TreeReader + TreeWriter + Send + Sync,
{
    fn process_transaction(&mut self, transaction: Transaction) -> Result<Proof> {
        match &transaction.operation {
            Operation::AddKey { .. } | Operation::RevokeKey { .. } | Operation::AddData { .. } => {
                let key_hash = KeyHash::with::<TreeHasher>(&transaction.id);

                debug!("updating account for user id {}", transaction.id);
                let proof = self.update(key_hash, transaction)?;

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

                let account_key_hash = KeyHash::with::<TreeHasher>(id);

                // Verify that the account doesn't already exist
                if matches!(self.get(account_key_hash)?, Found(_, _)) {
                    bail!(DatabaseError::NotFoundError(format!(
                        "Account already exists for ID {}",
                        id
                    )));
                }

                let service_key_hash = KeyHash::with::<TreeHasher>(service_id);

                let Found(service_account, _) = self.get(service_key_hash)? else {
                    bail!("Failed to get account for service ID {}", service_id);
                };

                let Some(service_challenge) = service_account.service_challenge else {
                    bail!("Service account does not contain a service challenge");
                };

                // Hash and sign credentials that have been signed by the external service
                let hash =
                    Digest::hash_items(&[id.as_bytes(), service_id.as_bytes(), &key.to_bytes()]);

                let ServiceChallenge::Signed(service_pubkey) = service_challenge;
                let ServiceChallengeInput::Signed(challenge_signature) = &challenge;

                // service_pubkey.verify_signature(&hash.to_bytes(), challenge_signature)?;

                debug!("creating new account for user ID {}", id);

                let insert_proof = self.insert(account_key_hash, transaction)?;
                Ok(Proof::Insert(Box::new(insert_proof)))
            }
            Operation::RegisterService { id, .. } => {
                ensure!(
                    transaction.id == id.as_str(),
                    "Id of transaction needs to be equal to operation id"
                );

                let key_hash = KeyHash::with::<TreeHasher>(id);

                debug!("creating new account for service id {}", id);

                let insert_proof = self.insert(key_hash, transaction)?;
                Ok(Proof::Insert(Box::new(insert_proof)))
            }
        }
    }

    fn insert(&mut self, key: KeyHash, transaction: Transaction) -> Result<InsertProof> {
        let old_root = self.get_commitment()?;
        let (None, non_membership_merkle_proof) = self.jmt.get_with_proof(key, self.epoch)? else {
            bail!("Key already exists");
        };

        let non_membership_proof = NonMembershipProof {
            root: old_root,
            proof: non_membership_merkle_proof,
            key,
        };

        let mut account = Account::default();
        account.process_transaction(&transaction)?;
        let serialized_account = account.encode_to_bytes()?;

        // the update proof just contains another nm proof
        let (new_root, _, tree_update_batch) = self
            .jmt
            .put_value_set_with_proof(vec![(key, Some(serialized_account))], self.epoch + 1)?;
        self.queue_batch(tree_update_batch);
        self.write_batch()?;

        let (_, membership_proof) = self.jmt.get_with_proof(key, self.epoch)?;

        Ok(InsertProof {
            new_root: Digest(new_root.0),
            tx: transaction,
            non_membership_proof,
            membership_proof,
        })
    }

    fn update(&mut self, key: KeyHash, transaction: Transaction) -> Result<UpdateProof> {
        let old_root = self.get_current_root()?;
        let (Some(old_serialized_account), inclusion_proof) =
            self.jmt.get_with_proof(key, self.epoch)?
        else {
            // TODO for wednesday Ryan: this should be getting hit but its not (test_update_non_existing_key)
            bail!("Key does not exist");
        };

        let old_account = Account::decode_from_bytes(&old_serialized_account)?;

        let mut new_account = old_account.clone();
        new_account.process_transaction(&transaction)?;

        let serialized_value = new_account.encode_to_bytes()?;

        let (new_root, update_proof, tree_update_batch) = self.jmt.put_value_set_with_proof(
            vec![(key, Some(serialized_value.clone()))],
            self.epoch + 1,
        )?;
        self.queue_batch(tree_update_batch);
        self.write_batch()?;

        Ok(UpdateProof {
            old_root: Digest(old_root.0),
            new_root: Digest(new_root.0),
            inclusion_proof,
            old_account,
            key,
            update_proof,
            tx: transaction,
        })
    }

    fn get(&self, key: KeyHash) -> Result<AccountResponse> {
        let root = self.get_commitment()?;
        let (value, proof) = self.jmt.get_with_proof(key, self.epoch)?;

        match value {
            Some(serialized_value) => {
                let deserialized_value = Account::decode_from_bytes(&serialized_value)?;
                let membership_proof = MembershipProof {
                    root,
                    proof,
                    key,
                    value: deserialized_value.clone(),
                };
                Ok(Found(Box::new(deserialized_value), membership_proof))
            }
            None => {
                let non_membership_proof = NonMembershipProof { root, proof, key };
                Ok(NotFound(non_membership_proof))
            }
        }
    }
}
