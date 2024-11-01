use anyhow::{anyhow, bail, Result};
use jmt::KeyHash;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

use crate::{
    digest::Digest,
    hasher::Hasher,
    keys::VerifyingKey,
    operation::{Operation, OperationType},
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Hashchain {
    pub id: String,
    pub entries: Vec<HashchainEntry>,
}

impl IntoIterator for Hashchain {
    type Item = HashchainEntry;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a Hashchain {
    type Item = &'a HashchainEntry;
    type IntoIter = std::slice::Iter<'a, HashchainEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl<'a> IntoIterator for &'a mut Hashchain {
    type Item = &'a mut HashchainEntry;
    type IntoIter = std::slice::IterMut<'a, HashchainEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter_mut()
    }
}

impl Deref for Hashchain {
    type Target = Vec<HashchainEntry>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl DerefMut for Hashchain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
    }
}

impl Hashchain {
    pub fn from_operation(operation: Operation) -> Result<Self> {
        let mut hc = Hashchain::empty(operation.id.clone());
        hc.perform_operation(operation)?;
        Ok(hc)
    }

    pub fn empty(id: String) -> Self {
        Self {
            id,
            entries: Vec::new(),
        }
    }

    pub fn get_key_at_index(&self, idx: usize) -> Result<&VerifyingKey> {
        self.entries
            .get(idx)
            .and_then(|entry| entry.operation.get_public_key())
            .ok_or_else(|| anyhow!("No valid public key found at index {}", idx))
    }

    pub fn get_valid_keys(&self) -> HashSet<VerifyingKey> {
        let mut valid_keys: HashSet<VerifyingKey> = HashSet::new();

        for entry in self.entries.clone() {
            match &entry.operation.op {
                OperationType::RegisterService { .. } | OperationType::AddData { .. } => {}
                OperationType::AddKey | OperationType::CreateAccount { .. } => {
                    let key = entry.operation.get_public_key().unwrap();
                    valid_keys.insert(key.clone());
                }
                OperationType::RevokeKey => {
                    let key = entry.operation.get_public_key().unwrap();
                    valid_keys.remove(&key.clone());
                }
            }
        }
        valid_keys
    }

    pub fn is_key_invalid(&self, key: &VerifyingKey) -> bool {
        self.iter()
            .rev()
            .find_map(|entry| {
                let value = entry.operation.get_public_key();
                match &entry.operation.op {
                    OperationType::RevokeKey { .. } if key.eq(value.unwrap()) => Some(true),
                    OperationType::AddKey { .. } | OperationType::CreateAccount { .. }
                        if key.eq(value.unwrap()) =>
                    {
                        Some(false)
                    }
                    _ => None,
                }
            })
            .unwrap_or(true)
    }

    pub fn get(&self, idx: usize) -> &HashchainEntry {
        &self.entries[idx]
    }

    pub fn last_hash(&self) -> Digest {
        self.last().map_or(Digest::zero(), |entry| entry.hash)
    }

    fn push(&mut self, operation: Operation) -> Result<HashchainEntry> {
        if operation.id != self.id {
            bail!("Operation ID does not match Hashchain ID");
        }

        let previous_hash = self.last_hash();

        let entry = HashchainEntry::new(operation, previous_hash);
        self.entries.push(entry.clone());

        Ok(entry)
    }

    // Validates and performs a new operation on the hashchain.
    pub fn perform_operation(&mut self, operation: Operation) -> Result<HashchainEntry> {
        self.validate_new_operation(&operation)?;
        self.push(operation)
    }

    /// Verifies the structure and signature of a new operation
    fn validate_new_operation(&self, operation: &Operation) -> Result<()> {
        operation.validate_basic()?;

        let last_hash = self.last_hash();
        if operation.prev_hash != last_hash {
            bail!(
                "Previous hash for key operation must be the last hash - prev: {}, last: {}",
                operation.prev_hash,
                last_hash
            )
        }
        let vk = match &operation.op {
            OperationType::CreateAccount { .. } | OperationType::RegisterService { .. } => {
                if !self.entries.is_empty() {
                    bail!("CreateAccount or RegisterService operation must be the first entry");
                }

                &operation.new_key.clone().unwrap()
            }
            OperationType::AddKey { .. }
            | OperationType::RevokeKey { .. }
            | OperationType::AddData { .. } => {
                if self.entries.is_empty() {
                    bail!("CreateAccount or RegisterService operation must be the first entry");
                }

                let Some(key_idx) = operation.signer_ref else {
                    bail!("Key operation must be signed by an existing key")
                };
                let verifying_key = self.get_key_at_index(key_idx)?;

                if self.is_key_invalid(verifying_key) {
                    bail!(
                        "The key at index {}, intended to verify this operation, is invalid",
                        key_idx
                    );
                }

                verifying_key
            }
        };

        operation.validate_signature(vk)
    }

    pub fn get_keyhash(&self) -> KeyHash {
        KeyHash::with::<Hasher>(Digest::hash(self.id.clone()))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
// A [`HashchainEntry`] represents a single entry in an account's hashchain.
// The value in the leaf of the corresponding account's node in the IMT is the hash of the last node in the hashchain.
pub struct HashchainEntry {
    pub hash: Digest,
    pub previous_hash: Digest,
    pub operation: Operation,
}

impl HashchainEntry {
    pub fn new(operation: Operation, previous_hash: Digest) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(operation.to_string().as_bytes());
        data.extend_from_slice(previous_hash.as_ref());
        let hash = Digest::hash(data);

        Self {
            hash,
            previous_hash,
            operation,
        }
    }
}
