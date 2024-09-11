use anyhow::{bail, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use jmt::KeyHash;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

use crate::{
    operation::{AccountSource, Operation},
    tree::{hash, Digest, Hasher},
};

#[derive(Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, PartialEq)]
pub struct Hashchain {
    id: String,
    entries: Vec<HashchainEntry>,
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
    pub fn new(id: String) -> Self {
        Self {
            id,
            entries: Vec::new(),
        }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, HashchainEntry> {
        self.entries.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, HashchainEntry> {
        self.entries.iter_mut()
    }

    pub fn create_account(&mut self, value: String, source: AccountSource) -> Result<Digest> {
        let operation = Operation::CreateAccount {
            id: self.id.clone(),
            value,
            source,
        };
        self.push(operation)
    }

    pub fn get(&self, idx: usize) -> &HashchainEntry {
        &self.entries[idx]
    }

    pub fn push(&mut self, operation: Operation) -> Result<Digest> {
        if let Operation::CreateAccount { .. } = operation {
            bail!("Cannot CreateAccount on an already existing hashchain");
        }
        if operation.id() != self.id {
            bail!("Operation ID does not match Hashchain ID");
        }

        let previous_hash = self
            .entries
            .last()
            .map_or(Digest::new([0u8; 32]), |entry| entry.hash);

        let entry = HashchainEntry::new(operation, previous_hash);
        self.entries.push(entry.clone());

        Ok(entry.hash)
    }

    // TODO: Obviously, this needs to be authenticated by an existing key.
    pub fn add(&mut self, value: String) -> Result<Digest> {
        let operation = Operation::Add {
            id: self.id.clone(),
            value,
        };
        self.push(operation)
    }

    pub fn revoke(&mut self, value: String) -> Result<Digest> {
        let operation = Operation::Revoke {
            id: self.id.clone(),
            value,
        };
        self.push(operation)
    }

    pub fn get_keyhash(&self) -> KeyHash {
        KeyHash::with::<Hasher>(self.id.clone())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, PartialEq)]
// A [`HashchainEntry`] represents a single entry in an account's hashchain.
// The value in the leaf of the corresponding account's node in the IMT is the hash of the last node in the hashchain.
pub struct HashchainEntry {
    pub hash: Digest,
    pub previous_hash: Digest,
    pub operation: Operation,
}

impl HashchainEntry {
    pub fn new(operation: Operation, previous_hash: Digest) -> Self {
        let hash = {
            let mut data = Vec::new();
            data.extend_from_slice(operation.to_string().as_bytes());
            data.extend_from_slice(previous_hash.as_ref());
            // TODO: replace with sha256 after JMT complete
            hash(&data)
        };
        Self {
            hash,
            previous_hash,
            operation,
        }
    }
}
