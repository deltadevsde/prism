use crate::{
    digest::Digest,
    hashchain::HashchainEntry,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput},
    transaction::Transaction,
    tree::{
        HashchainResponse::{self, *},
        InsertProof, Proof, UpdateProof,
    },
};
use anyhow::{bail, ensure, Result};
use prism_errors::DatabaseError;

pub trait HashchainStorage: Sync + Send {
    fn process_transaction(&mut self, transaction: Transaction) -> Result<Proof> {
        match &transaction.entry.operation {
            Operation::AddKey { .. } | Operation::RevokeKey { .. } | Operation::AddData { .. } => {
                debug!("updating hashchain for user id {}", transaction.id);
                let proof = self.update(transaction.id, transaction.entry)?;

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

                // Verify that the account doesn't already exist
                if matches!(self.get(id)?, Found(_, _)) {
                    bail!(DatabaseError::NotFoundError(format!(
                        "Account already exists for ID {}",
                        id
                    )));
                }

                let Found(service_hashchain, _) = self.get(service_id)? else {
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
                    Digest::hash_items(&[id.as_bytes(), service_id.as_bytes(), &key.as_bytes()]);

                let ServiceChallenge::Signed(service_pubkey) = creation_gate;
                let ServiceChallengeInput::Signed(challenge_signature) = &challenge;

                service_pubkey.verify_signature(&hash.to_bytes(), challenge_signature)?;

                debug!("creating new hashchain for user ID {}", id);

                let insert_proof = self.insert(id.clone(), transaction.entry)?;
                Ok(Proof::Insert(Box::new(insert_proof)))
            }
            Operation::RegisterService { id, .. } => {
                ensure!(
                    transaction.id == id.as_str(),
                    "Id of transaction needs to be equal to operation id"
                );

                debug!("creating new hashchain for service id {}", id);

                let insert_proof = self.insert(id.clone(), transaction.entry)?;
                Ok(Proof::Insert(Box::new(insert_proof)))
            }
        }
    }
    fn get(&self, id: &str) -> Result<HashchainResponse>;
    fn insert(&mut self, id: String, entry: HashchainEntry) -> Result<InsertProof>;
    fn update(&mut self, id: String, entry: HashchainEntry) -> Result<UpdateProof>;
    fn get_commitment(&self) -> Result<Digest>;
}
