use anyhow::{anyhow, bail, ensure, Result};
use prism_keys::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

use crate::{
    digest::Digest,
    operation::{
        HashchainSignatureBundle, Operation, ServiceChallenge, ServiceChallengeInput,
        SignatureBundle,
    },
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Hashchain {
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
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn from_entry(entry: HashchainEntry) -> Result<Self> {
        let mut hc = Hashchain::empty();
        hc.add_entry(entry)?;
        Ok(hc)
    }

    pub fn get_key_at_index(&self, idx: usize) -> Result<&VerifyingKey> {
        self.entries
            .get(idx)
            .and_then(|entry| entry.operation.get_public_key())
            .ok_or_else(|| anyhow!("No public key found at index {}", idx))
    }

    pub fn is_key_invalid(&self, key: &VerifyingKey) -> bool {
        for entry in self.iter().rev() {
            if let Some(entry_key) = entry.operation.get_public_key() {
                if key.eq(entry_key) {
                    match entry.operation {
                        Operation::RevokeKey { .. } => return true,
                        Operation::AddKey { .. }
                        | Operation::CreateAccount { .. }
                        | Operation::RegisterService { .. } => return false,
                        _ => {}
                    }
                }
            }
        }
        true
    }

    pub fn get(&self, idx: usize) -> &HashchainEntry {
        &self.entries[idx]
    }

    pub fn last_hash(&self) -> Digest {
        self.last().map_or(Digest::zero(), |entry| entry.hash)
    }

    /// Validates and adds a new entry to the hashchain.
    /// This method is ran in circuit.
    pub fn add_entry(&mut self, entry: HashchainEntry) -> Result<()> {
        self.validate_new_entry(&entry)?;
        self.entries.push(entry);
        Ok(())
    }

    pub fn register_service(
        &mut self,
        id: String,
        creation_gate: ServiceChallenge,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<HashchainEntry> {
        let entry = HashchainEntry::new_register_service(id, creation_gate, key, signing_key);
        self.add_entry(entry.clone())?;
        Ok(entry)
    }

    pub fn create_account(
        &mut self,
        id: String,
        service_id: String,
        challenge: ServiceChallengeInput,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<HashchainEntry> {
        let entry = HashchainEntry::new_create_account(id, service_id, challenge, key, signing_key);
        self.add_entry(entry.clone())?;
        Ok(entry)
    }

    pub fn add_key(
        &mut self,
        key: VerifyingKey,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Result<HashchainEntry> {
        let entry = HashchainEntry::new_add_key(key, self.last_hash(), signing_key, key_idx);
        self.add_entry(entry.clone())?;
        Ok(entry)
    }

    pub fn revoke_key(
        &mut self,
        key: VerifyingKey,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Result<HashchainEntry> {
        let entry = HashchainEntry::new_revoke_key(key, self.last_hash(), signing_key, key_idx);
        self.add_entry(entry.clone())?;
        Ok(entry)
    }

    pub fn add_data(
        &mut self,
        data: Vec<u8>,
        data_signature: Option<SignatureBundle>,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Result<HashchainEntry> {
        let entry = HashchainEntry::new_add_data(
            data,
            data_signature,
            self.last_hash(),
            signing_key,
            key_idx,
        );
        self.add_entry(entry.clone())?;
        Ok(entry)
    }

    /// Validates that the new entry is valid and can be added to the hashchain.
    /// This method is ran in circuit.
    fn validate_new_entry(&self, entry: &HashchainEntry) -> Result<()> {
        entry.validate_operation()?;

        let last_hash = self.last_hash();
        if entry.previous_hash != last_hash {
            bail!(
                "Previous hash for new entry must be the last hash - prev: {}, last: {}",
                entry.previous_hash,
                last_hash
            )
        }

        let verifying_key = self.verifying_key_for_entry(entry)?;

        match entry.operation {
            Operation::CreateAccount { .. } | Operation::RegisterService { .. } => {
                if !self.entries.is_empty() {
                    bail!("CreateAccount/RegisterService must be the first entry");
                }
            }
            Operation::AddData { .. } | Operation::AddKey { .. } | Operation::RevokeKey { .. } => {
                if self.entries.is_empty() {
                    bail!("CreateAccount/RegisterService must be the first entry");
                }

                if self.is_key_invalid(verifying_key) {
                    bail!("Invalid key at index {}", &entry.signature_bundle.key_idx);
                }
            }
        }

        entry.validate_hash()?;
        entry.validate_signature(verifying_key)
    }

    fn verifying_key_for_entry<'a>(
        &'a self,
        entry: &'a HashchainEntry,
    ) -> Result<&'a VerifyingKey> {
        match &entry.operation {
            Operation::CreateAccount { key, .. } | Operation::RegisterService { key, .. } => {
                Ok(key)
            }
            Operation::AddData { .. } | Operation::AddKey { .. } | Operation::RevokeKey { .. } => {
                self.get_key_at_index(entry.signature_bundle.key_idx)
            }
        }
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
    pub signature_bundle: HashchainSignatureBundle,
}

impl HashchainEntry {
    pub fn new(
        operation: Operation,
        previous_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Self {
        let serialized_operation =
            bincode::serialize(&operation).expect("Serializing operation should work");
        let hash =
            Digest::hash_items(&[serialized_operation.as_slice(), &previous_hash.to_bytes()]);

        let signature_bundle = HashchainSignatureBundle {
            signature: signing_key.sign(hash.as_ref()),
            key_idx,
        };

        Self {
            hash,
            previous_hash,
            operation,
            signature_bundle,
        }
    }

    pub fn new_genesis(operation: Operation, signing_key: &SigningKey) -> Self {
        Self::new(operation, Digest::zero(), signing_key, 0)
    }

    pub fn new_register_service(
        id: String,
        creation_gate: ServiceChallenge,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Self {
        let operation = Operation::RegisterService {
            id,
            creation_gate,
            key,
        };
        Self::new_genesis(operation, signing_key)
    }

    pub fn new_create_account(
        id: String,
        service_id: String,
        challenge: ServiceChallengeInput,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Self {
        let operation = Operation::CreateAccount {
            id,
            service_id,
            challenge,
            key,
        };
        Self::new_genesis(operation, signing_key)
    }

    pub fn new_add_key(
        key: VerifyingKey,
        prev_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Self {
        let operation = Operation::AddKey { key };
        Self::new(operation, prev_hash, signing_key, key_idx)
    }

    pub fn new_revoke_key(
        key: VerifyingKey,
        prev_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Self {
        let operation = Operation::RevokeKey { key };
        Self::new(operation, prev_hash, signing_key, key_idx)
    }

    pub fn new_add_data(
        data: Vec<u8>,
        data_signature: Option<SignatureBundle>,
        prev_hash: Digest,
        signing_key: &SigningKey,
        key_idx: usize,
    ) -> Self {
        let operation = Operation::AddData {
            data,
            data_signature,
        };
        Self::new(operation, prev_hash, signing_key, key_idx)
    }

    pub fn validate_hash(&self) -> Result<()> {
        let pristine_entry = self.without_signature();

        let serialized_operation = bincode::serialize(&pristine_entry.operation)?;
        let pristine_entry_hash = Digest::hash_items(&[
            serialized_operation.as_slice(),
            &pristine_entry.previous_hash.to_bytes(),
        ]);

        ensure!(
            self.hash == pristine_entry_hash,
            "Hashchain entry has incorrect hash"
        );
        Ok(())
    }

    pub fn validate_signature(&self, verifying_key: &VerifyingKey) -> Result<()> {
        verifying_key.verify_signature(self.hash.as_ref(), &self.signature_bundle.signature)
    }

    pub fn validate_operation(&self) -> Result<()> {
        self.operation.validate_basic()
    }

    pub fn without_signature(&self) -> Self {
        Self {
            signature_bundle: HashchainSignatureBundle {
                key_idx: self.signature_bundle.key_idx,
                signature: Signature::Placeholder,
            },
            ..self.clone()
        }
    }
}
