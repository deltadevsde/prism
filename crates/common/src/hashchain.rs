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
        AddSignedDataArgs, CreateAccountArgs, KeyOperationArgs, Operation, RegisterServiceArgs,
        ServiceChallenge, ServiceChallengeInput,
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
        if self.entries.is_empty() {
            return Ok(());
        }

        let mut valid_keys: HashSet<VerifyingKey> = HashSet::new();

        for (index, entry) in self.entries.iter().enumerate().take(self.entries.len() - 1) {
            match &entry.operation {
                Operation::RegisterService(_) => {
                    if index != 0 {
                        bail!("RegisterService operation must be the first entry");
                    }
                }
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
                Operation::AddSignedData(_) => {}
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
            // TODO: RegisterService should not be permissionless at first, until we have state bloat metrics
            Operation::RegisterService(_) => {
                if last_index != 0 {
                    bail!("RegisterService operation must be the first entry");
                }
            }
            Operation::CreateAccount(args) => {
                if last_index != 0 {
                    bail!("CreateAccount operation must be the first entry");
                }
                args.value.verify_signature(
                    &bincode::serialize(
                        &last_entry.operation.without_signature().without_challenge(),
                    )?,
                    &args.signature,
                )?;
            }
            Operation::AddKey(args) | Operation::RevokeKey(args) => {
                let message = bincode::serialize(&last_entry.operation.without_signature())?;

                self.verify_signature_at_key_idx(
                    &message,
                    &args.signature.signature,
                    args.signature.key_idx,
                    &valid_keys,
                )?;
            }
            Operation::AddSignedData(args) => {
                self.verify_signature_at_key_idx(
                    &args.value,
                    &args.signature.signature,
                    args.signature.key_idx,
                    &valid_keys,
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
                Operation::RegisterService(_) | Operation::AddSignedData(_) => {}
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

    fn verify_signature_at_key_idx(
        &self,
        value: &[u8],
        signature: &[u8],
        idx: usize,
        valid_keys: &HashSet<VerifyingKey>,
    ) -> Result<()> {
        let verifying_key = self.get_key_at_index(idx)?;
        if !valid_keys.contains(verifying_key) {
            bail!(
                "Key intended to verify signature {:?} is not in valid keys {:?}",
                verifying_key,
                valid_keys
            );
        }
        verifying_key.verify_signature(value, signature)
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

    /// Verifies the structure and signature of a new operation without checking if the key is revoked.
    fn validate_new_operation(&self, operation: &Operation) -> Result<()> {
        match operation {
            Operation::RegisterService(_) => {
                if !self.entries.is_empty() {
                    bail!("RegisterService operation must be the first entry");
                }
                Ok(())
            }
            Operation::AddKey(KeyOperationArgs { signature, .. })
            | Operation::RevokeKey(KeyOperationArgs { signature, .. })
            | Operation::AddSignedData(AddSignedDataArgs { signature, .. }) => {
                let signing_key = self.get_key_at_index(signature.key_idx)?;

                if self.is_key_revoked(signing_key.clone()) {
                    bail!("The signing key is revoked");
                }

                operation.verify_user_signature(signing_key.clone())
            }
            Operation::CreateAccount(args) => {
                if !self.entries.is_empty() {
                    bail!("RegisterService operation must be the first entry");
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
