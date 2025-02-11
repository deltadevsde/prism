use prism_common::{account::Account, digest::Digest};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
/// Request to retrieve account information
pub struct AccountRequest {
    /// Identifier for the account to look up
    pub id: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
/// Response containing account data and a corresponding Merkle proof
pub struct AccountResponse {
    /// The account if found, or None if not found
    pub account: Option<Account>,
    /// Merkle proof for account membership or non-membership
    pub proof: HashedMerkleProof,
}

#[derive(Serialize, Deserialize, ToSchema)]
/// Response representing a cryptographic commitment towards the current state of prism
pub struct CommitmentResponse {
    /// Commitment as root hash of Merkle tree
    pub commitment: Digest,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[schema(example = r#"{
    "leaf": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "siblings": [
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
    ]
}"#)]
/// A compact representation of a Merkle proof where the nodes are represented by their hash values.
/// Used to verify the inclusion or exclusion of data in a Merkle tree.
pub struct HashedMerkleProof {
    /// The hash of the leaf node being proven, if it exists. None if proving non-existence.
    pub leaf: Option<Digest>,
    /// The hashes of sibling nodes along the path from the leaf to the root.
    pub siblings: Vec<Digest>,
}

impl HashedMerkleProof {
    pub fn empty() -> Self {
        Self {
            leaf: None,
            siblings: vec![],
        }
    }
}
