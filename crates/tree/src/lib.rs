pub mod hasher;
pub mod key_directory_tree;
pub mod proofs;
pub mod snarkable_tree;

use prism_common::account::Account;
use proofs::MerkleProof;

/// Enumerates possible responses when fetching tree values
#[derive(Debug)]
pub enum AccountResponse {
    /// When an account was found, provides the value and its corresponding membership-proof
    Found(Box<Account>, MerkleProof),

    /// When no account was found for a specific key, provides the corresponding
    /// non-membership-proof
    NotFound(MerkleProof),
}

#[cfg(test)]
mod tests;
