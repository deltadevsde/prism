use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jmt::KeyHash;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

use crate::{
    operation::{CreateAccountArgs, Operation, PublicKey, ServiceChallengeInput},
    tree::{hash, Digest, Hasher},
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
    pub fn new(id: String) -> Self {
        Self {
            id,
            entries: Vec::new(),
        }
    }

    pub fn verify_last_entry(&self) -> Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }

        let mut valid_keys: HashSet<PublicKey> = HashSet::new();

        for (index, entry) in self.entries.iter().enumerate().take(self.entries.len() - 1) {
            match &entry.operation {
                Operation::CreateAccount(args) => {
                    if index != 0 {
                        bail!("CreateAccount operation must be the first entry");
                    }
                    valid_keys.insert(args.value.clone());
                }
                Operation::AddKey(args) => {
                    valid_keys.insert(args.value.clone());
                }
                Operation::RevokeKey(args) => {
                    valid_keys.remove(&args.value);
                }
            }
        }

        let last_entry = self.entries.last().unwrap();
        let last_index = self.entries.len() - 1;
        if last_index > 0 {
            let prev_entry = &self.entries[last_index - 1];
            if last_entry.previous_hash != prev_entry.hash {
                bail!("Previous hash mismatch for the last entry");
            }
        }

        match &last_entry.operation {
            Operation::CreateAccount(args) => {
                if last_index != 0 {
                    bail!("CreateAccount operation must be the first entry");
                }
                self.verify_signature(
                    &args.value,
                    &bincode::serialize(&last_entry.operation.without_signature())?,
                    &args.signature,
                )?;
            }
            Operation::AddKey(args) | Operation::RevokeKey(args) => {
                let signing_key = self.get_key_at_index(args.signature.key_idx as usize)?;
                if !valid_keys.contains(signing_key) {
                    bail!("Last operation signed with revoked or non-existent key");
                }
                self.verify_signature(
                    signing_key,
                    &bincode::serialize(&last_entry.operation.without_signature())?,
                    &args.signature.signature,
                )?;
            }
        }

        Ok(())
    }

    pub(crate) fn insert_unsafe(&self, new_entry: HashchainEntry) -> Hashchain {
        let mut new = self.clone();
        new.entries.push(new_entry);
        new
    }

    pub fn get_key_at_index(&self, idx: usize) -> Result<&PublicKey> {
        self.entries
            .get(idx)
            .and_then(|entry| entry.operation.get_public_key())
            .ok_or_else(|| anyhow!("No valid public key found at index {}", idx))
    }

    pub fn get_valid_keys(&self) -> HashSet<PublicKey> {
        let mut valid_keys: HashSet<PublicKey> = HashSet::new();

        for entry in self.entries.clone() {
            match &entry.operation {
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

    pub fn is_key_revoked(&self, key: PublicKey) -> bool {
        self.iter()
            .rev()
            .find_map(|entry| match entry.operation.clone() {
                Operation::RevokeKey(args) if args.value == key => Some(true),
                Operation::AddKey(args) if args.value == key => Some(false),
                Operation::CreateAccount(args) if args.value == key => Some(false),
                _ => None,
            })
            .unwrap_or(false)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, HashchainEntry> {
        self.entries.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, HashchainEntry> {
        self.entries.iter_mut()
    }

    pub fn create_account(
        &mut self,
        value: PublicKey,
        signature: Vec<u8>,
        service_id: String,
        challenge: ServiceChallengeInput,
    ) -> Result<HashchainEntry> {
        let operation = Operation::CreateAccount(CreateAccountArgs {
            id: self.id.clone(),
            signature,
            value,
            service_id,
            challenge,
        });
        self.push(operation)
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

    fn validate_new_operation(&self, operation: &Operation) -> Result<()> {
        match operation {
            Operation::AddKey(args) | Operation::RevokeKey(args) => {
                let signing_key = self.get_key_at_index(args.signature.key_idx as usize)?;

                if self.is_key_revoked(signing_key.clone()) {
                    bail!("The signing key is revoked");
                }

                let message = bincode::serialize(&operation.without_signature())?;
                self.verify_signature(signing_key, &message, &args.signature.signature)
            }
            Operation::CreateAccount(args) => {
                let message = bincode::serialize(&operation.without_signature())?;
                self.verify_signature(&args.value, &message, &args.signature)
            }
        }
    }

    pub fn verify_signature(
        &self,
        public_key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let PublicKey::Ed25519(key_bytes) = public_key;

        let verifying_key = VerifyingKey::from_bytes(key_bytes.as_slice().try_into()?)?;
        let signature = Signature::from_slice(signature)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))
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
        let hash = {
            let mut data = Vec::new();
            data.extend_from_slice(operation.to_string().as_bytes());
            data.extend_from_slice(previous_hash.as_ref());
            hash(&data)
        };
        Self {
            hash,
            previous_hash,
            operation,
        }
    }
}
