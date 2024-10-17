use anyhow::{anyhow, bail, Result};
use jmt::KeyHash;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

use crate::{
    keys::VerifyingKey,
    operation::{
        CreateAccountArgs, Operation, RegisterServiceArgs, ServiceChallenge, ServiceChallengeInput,
    },
    tree::{Digest, Hasher},
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
        let mut hc = Hashchain::empty(operation.id());
        hc.perform_operation(operation)?;
        Ok(hc)
    }

    pub fn create_account(
        id: String,
        value: VerifyingKey,
        signature: Vec<u8>,
        service_id: String,
        challenge: ServiceChallengeInput,
    ) -> Result<Hashchain> {
        let mut hc = Hashchain::empty(id.clone());
        let operation = Operation::CreateAccount(CreateAccountArgs {
            id,
            signature,
            value,
            service_id,
            challenge,
        });
        hc.perform_operation(operation)?;
        Ok(hc)
    }

    pub fn register_service(id: String, challenge: ServiceChallenge) -> Result<Hashchain> {
        let mut hc = Hashchain::empty(id.clone());
        let operation = Operation::RegisterService(RegisterServiceArgs {
            id,
            creation_gate: challenge,
        });
        hc.perform_operation(operation)?;
        Ok(hc)
    }

    pub fn empty(id: String) -> Self {
        Self {
            id,
            entries: Vec::new(),
        }
    }

    pub fn verify_last_entry(&self) -> Result<()> {
        let mut rev_iter = self.iter().enumerate().rev();

        let Some((last_idx, last_entry)) = rev_iter.next() else {
            // When there is no entry at all, consider it verified
            return Ok(());
        };

        let Some((second_last_idx, second_last_entry)) = rev_iter.next() else {
            // When there is only 1 item in the chain, validate insertion at idx 0
            return self.validate_operation_at_idx(&last_entry.operation, last_idx);
        };

        // When there are 2 or more items in the chain, validate insertion at 2nd last index
        if last_entry.previous_hash != second_last_entry.hash {
            bail!("Previous hash mismatch for the last entry");
        }

        self.validate_operation_at_idx(&last_entry.operation, second_last_idx)
    }

    pub(crate) fn insert_unsafe(&self, new_entry: HashchainEntry) -> Hashchain {
        let mut new = self.clone();
        new.entries.push(new_entry);
        new
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
                Operation::RegisterService(_) => {}
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

    pub fn is_key_revoked(&self, key: VerifyingKey) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        self.is_key_revoked_before_idx(key, self.entries.len() - 1)
    }

    fn is_key_revoked_before_idx(&self, key: VerifyingKey, idx: usize) -> bool {
        self.iter()
            .skip(idx)
            .rev()
            .find_map(|entry| match entry.operation.clone() {
                Operation::RevokeKey(args) if args.value == key => Some(true),
                Operation::AddKey(args) if args.value == key => Some(false),
                Operation::CreateAccount(args) if args.value == key => Some(false),
                _ => None,
            })
            .unwrap_or(true)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, HashchainEntry> {
        self.entries.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, HashchainEntry> {
        self.entries.iter_mut()
    }

    pub fn get(&self, idx: usize) -> &HashchainEntry {
        &self.entries[idx]
    }

    fn push(&mut self, operation: Operation) -> Result<HashchainEntry> {
        if operation.id() != self.id {
            bail!("Operation ID does not match Hashchain ID");
        }

        let previous_hash = self
            .entries
            .last()
            .map_or(Digest::new([0u8; 32]), |entry| entry.hash);

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
        if self.entries.is_empty() {
            return self.validate_operation_at_idx(operation, 0);
        }

        self.validate_operation_at_idx(operation, self.entries.len() - 1)
    }

    fn validate_operation_at_idx(&self, operation: &Operation, idx: usize) -> Result<()> {
        println!("Validating op {}", operation);
        match operation {
            Operation::RegisterService(_) => {
                if idx > 0 {
                    bail!("RegisterService operation must be the first entry");
                }
                Ok(())
            }
            Operation::AddKey(args) | Operation::RevokeKey(args) => {
                let signing_key = self.get_key_at_index(args.signature.key_idx as usize)?;

                if self.is_key_revoked_before_idx(signing_key.clone(), idx) {
                    bail!("The signing key is revoked");
                }

                operation.verify_user_signature(signing_key.clone())
            }
            Operation::CreateAccount(args) => {
                if idx > 0 {
                    bail!("CreateAccount operation must be the first entry");
                }
                operation.verify_user_signature(args.value.clone())
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
