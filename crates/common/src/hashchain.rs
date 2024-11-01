use anyhow::{anyhow, bail, Result};
use jmt::KeyHash;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

use crate::{digest::Digest, hasher::Hasher, keys::VerifyingKey, operation::Operation};

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
        let mut hc = Hashchain::empty(operation.id());
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
            match &entry.operation {
                Operation::RegisterService(_) | Operation::AddData(_) => {}
                Operation::CreateAccount(args) => {
                    valid_keys.insert(args.value.clone());
                }
                Operation::AddKey(args) => {
                    valid_keys.insert(args.value.clone());
                }
                Operation::RevokeKey(args) => {
                    valid_keys.remove(&args.value.clone());
                }
            }
        }
        valid_keys
    }

    pub fn is_key_invalid(&self, key: VerifyingKey) -> bool {
        self.iter()
            .rev()
            .find_map(|entry| match entry.operation.clone() {
                Operation::RevokeKey(args) if args.value == key => Some(true),
                Operation::AddKey(args) if args.value == key => Some(false),
                Operation::CreateAccount(args) if args.value == key => Some(false),
                _ => None,
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
        if operation.id() != self.id {
            bail!("Operation ID does not match Hashchain ID");
        }

        let previous_hash = self.last_hash();

        let entry = HashchainEntry::new(operation, previous_hash);
        self.entries.push(entry.clone());

        Ok(entry)
    }

    pub fn perform_operation(&mut self, operation: Operation) -> Result<HashchainEntry> {
        self.validate_new_operation(&operation)?;
        self.push(operation)
    }

    /// Verifies the structure and signature of a new operation
    fn validate_new_operation(&self, operation: &Operation) -> Result<()> {
        match operation {
            Operation::RegisterService(args) => {
                if !self.entries.is_empty() {
                    bail!("RegisterService operation must be the first entry");
                }

                if args.prev_hash != Digest::zero() {
                    bail!(
                        "Previous hash for initial operation must be zero, but was {}",
                        args.prev_hash
                    )
                }

                Ok(())
            }
            Operation::AddKey(args) | Operation::RevokeKey(args) => {
                let last_hash = self.last_hash();
                if args.prev_hash != last_hash {
                    bail!(
                        "Previous hash for key operation must be the last hash - prev: {}, last: {}",
                        args.prev_hash,
                        last_hash
                    )
                }

                let key_idx = args.signature.key_idx;
                let verifying_key = self.get_key_at_index(key_idx)?;

                if self.is_key_invalid(verifying_key.clone()) {
                    bail!(
                        "The key at index {}, intended to verify this operation, is invalid",
                        key_idx
                    );
                }

                operation.verify_user_signature(verifying_key)
            }
            Operation::AddData(args) => {
                let last_hash = self.last_hash();
                if args.prev_hash != last_hash {
                    bail!(
                        "Previous hash for add-data operation is not equal to the last hash - prev: {}, last: {}",
                        args.prev_hash,
                        last_hash
                    )
                }

                let key_idx = args.op_signature.key_idx;
                let verifying_key = self.get_key_at_index(key_idx)?;

                if self.is_key_invalid(verifying_key.clone()) {
                    bail!(
                        "The key at index {}, intended to verify this operation, is invalid",
                        key_idx
                    );
                }

                operation.verify_user_signature(verifying_key)
            }
            Operation::CreateAccount(args) => {
                if !self.entries.is_empty() {
                    bail!("CreateAccount operation must be the first entry");
                }

                if args.prev_hash != Digest::zero() {
                    bail!("Previous hash for initial operation must be zero")
                }

                operation.verify_user_signature(&args.value)
            }
        }
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
