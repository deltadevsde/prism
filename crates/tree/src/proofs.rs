use std::collections::HashMap;

use jmt::{
    KeyHash, RootHash,
    proof::{SparseMerkleNode, SparseMerkleProof, UpdateMerkleProof},
};
use prism_common::{
    account::Account,
    digest::Digest,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput},
    transaction::Transaction,
};
use prism_errors::ProofError;
use prism_serde::binary::ToBinary;
use serde::{Deserialize, Serialize};

use crate::hasher::TreeHasher;

#[derive(Serialize, Deserialize)]
/// Represents a contiguous stream of [`Proof`]s leading from [`Batch::prev_root`] to
/// [`Batch::new_root`].
///
/// Used as the input to the circuit.
pub struct Batch {
    pub prev_root: Digest,
    pub new_root: Digest,

    pub service_proofs: HashMap<String, ServiceProof>,
    pub proofs: Vec<Proof>,
}

impl Batch {
    pub fn init(prev_root: Digest, next_root: Digest, proofs: Vec<Proof>) -> Self {
        Batch {
            prev_root,
            new_root: next_root,
            service_proofs: HashMap::new(),
            proofs,
        }
    }

    pub fn verify(&self) -> Result<(), ProofError> {
        let mut root = self.prev_root;
        for proof in &self.proofs {
            match proof {
                Proof::Insert(insert_proof) => {
                    // When verifying account creation, ensure service challenge is verified as well
                    let challenge = match &insert_proof.tx.operation {
                        Operation::CreateAccount { service_id, .. } => {
                            let service_challenge = self
                                .service_proofs
                                .get(service_id)
                                .and_then(|service_proof| service_proof.service_challenge());
                            if service_challenge.is_none() {
                                return Err(ProofError::MissingServiceChallenge(
                                    service_id.to_string(),
                                ));
                            }
                            service_challenge
                        }

                        _ => None,
                    };
                    insert_proof.verify(challenge)?;
                    root = insert_proof.new_root;
                }
                Proof::Update(update_proof) => {
                    update_proof.verify()?;
                    root = update_proof.new_root;
                }
            }
        }

        assert_eq!(root, self.new_root);
        for (id, service_proof) in &self.service_proofs {
            let keyhash = KeyHash::with::<TreeHasher>(&id);
            let serialized_account = service_proof.service.encode_to_bytes()?;
            service_proof
                .proof
                .verify_existence(RootHash(root.0), keyhash, serialized_account)
                .map_err(|e| ProofError::ExistenceError(e.to_string()))?;
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct ServiceProof {
    pub root: Digest,
    pub proof: SparseMerkleProof<TreeHasher>,
    pub service: Account,
}

impl ServiceProof {
    pub fn service_challenge(&self) -> Option<&ServiceChallenge> {
        self.service.service_challenge()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Proof {
    Update(Box<UpdateProof>),
    Insert(Box<InsertProof>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Represents an insertion proof for a newly created account.
///
/// Currently, this proof is generated by
/// [`crate::operation::Operation::CreateAccount`] and
/// [`crate::operation::Operation::RegisterService`] operations.
pub struct InsertProof {
    /// Proof that the key does not already exist in the tree (i.e. it's not overwriting an
    /// existing key)
    pub non_membership_proof: MerkleProof,

    /// Post-insertion root hash of the tree
    pub new_root: Digest,
    /// Proof that the new account is correctly inserted into the tree
    pub membership_proof: SparseMerkleProof<TreeHasher>,

    /// The new account that was inserted.
    pub tx: Transaction,
}

impl InsertProof {
    /// The method called in circuit to verify the state transition to the new root.
    pub fn verify(&self, service_challenge: Option<&ServiceChallenge>) -> Result<(), ProofError> {
        self.non_membership_proof
            .verify_nonexistence()
            .map_err(|e| ProofError::NonexistenceError(e.to_string()))?;
        let mut account = Account::default();
        account
            .process_transaction(&self.tx)
            .map_err(|e| ProofError::TransactionError(e.to_string()))?;

        // If we are creating an account, we need to additionally verify the service challenge
        if let Operation::CreateAccount {
            id,
            service_id,
            challenge,
            key,
        } = &self.tx.operation
        {
            let hash = Digest::hash_items(&[id.as_bytes(), service_id.as_bytes(), &key.to_bytes()]);

            if service_challenge.is_none() {
                return Err(ProofError::MissingServiceChallenge(service_id.to_string()));
            }

            let ServiceChallenge::Signed(challenge_vk) = service_challenge.unwrap();
            let ServiceChallengeInput::Signed(challenge_signature) = challenge;
            challenge_vk
                .verify_signature(hash, challenge_signature)
                .map_err(|e| ProofError::VerificationError(e.to_string()))?;
        }

        let serialized_account = account.encode_to_bytes()?;

        self.membership_proof
            .clone()
            .verify_existence(
                RootHash(self.new_root.0),
                self.non_membership_proof.key,
                serialized_account,
            )
            .map_err(|e| ProofError::VerificationError(e.to_string()))?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Represents an update proof for an existing [`Account`].
pub struct UpdateProof {
    pub old_root: Digest,
    pub new_root: Digest,

    pub key: KeyHash,

    pub old_account: Account,
    pub tx: Transaction,

    /// Inclusion proof of [`UpdateProof::old_account`]
    pub inclusion_proof: SparseMerkleProof<TreeHasher>,
    /// Update proof for [`UpdateProof::key`] to be updated with [`UpdateProof::tx`]
    pub update_proof: UpdateMerkleProof<TreeHasher>,
}

impl UpdateProof {
    /// The method called in circuit to verify the state transition to the new root.
    pub fn verify(&self) -> Result<(), ProofError> {
        // Verify existence of old value.
        // Otherwise, any arbitrary account could be set as old_account.
        let old_serialized_account = self.old_account.encode_to_bytes()?;
        self.inclusion_proof
            .verify_existence(RootHash(self.old_root.0), self.key, old_serialized_account)
            .map_err(|e| ProofError::VerificationError(e.to_string()))?;

        let mut new_account = self.old_account.clone();
        new_account
            .process_transaction(&self.tx)
            .map_err(|e| ProofError::TransactionError(e.to_string()))?;

        // Ensure the update proof corresponds to the new account value
        let new_serialized_account = new_account.encode_to_bytes()?;
        self.update_proof
            .clone()
            .verify_update(
                RootHash(self.old_root.0),
                RootHash(self.new_root.0),
                vec![(self.key, Some(new_serialized_account))],
            )
            .map_err(|e| ProofError::AccountError(e.to_string()))?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub root: Digest,
    pub proof: SparseMerkleProof<TreeHasher>,
    pub key: KeyHash,
}

impl MerkleProof {
    pub fn verify_existence(&self, value: &Account) -> Result<(), ProofError> {
        let value = value.encode_to_bytes()?;
        self.proof
            .verify_existence(RootHash(self.root.0), self.key, value)
            .map_err(|e| ProofError::VerificationError(e.to_string()))
    }

    pub fn verify_nonexistence(&self) -> Result<(), ProofError> {
        self.proof
            .verify_nonexistence(RootHash(self.root.0), self.key)
            .map_err(|e| ProofError::VerificationError(e.to_string()))
    }
}

impl MerkleProof {
    pub fn hashed(self) -> HashedMerkleProof {
        let leaf_hash = self.proof.leaf().map(|node| node.hash::<TreeHasher>()).map(Digest::new);
        let sibling_hashes = self
            .proof
            .siblings()
            .iter()
            .map(SparseMerkleNode::hash::<TreeHasher>)
            .map(Digest::new)
            .collect();
        HashedMerkleProof {
            leaf: leaf_hash,
            siblings: sibling_hashes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HashedMerkleProof {
    pub leaf: Option<Digest>,
    pub siblings: Vec<Digest>,
}
