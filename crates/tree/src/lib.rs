pub mod hasher;
pub mod key_directory_tree;
pub mod proofs;
pub mod snarkable_tree;

use prism_common::hashchain::Hashchain;
use proofs::{MembershipProof, NonMembershipProof};

/// Enumerates possible responses when fetching tree values
#[derive(Debug)]
pub enum HashchainResponse {
    /// When a hashchain was found, provides the value and its corresponding membership-proof
    Found(Hashchain, MembershipProof),

    /// When no hashchain was found for a specific key, provides the corresponding non-membership-proof
    NotFound(NonMembershipProof),
}

#[cfg(test)]
mod tests;
