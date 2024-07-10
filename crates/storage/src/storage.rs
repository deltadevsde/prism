use indexed_merkle_tree::tree::Proof;
use mockall::predicate::*;
use mockall::*;
use std::{self};

use deimos_errors::errors::{DatabaseError, DeimosError};
use deimos_types::types::{IncomingEntry, ChainEntry};

#[automock]
pub trait Database: Send + Sync {
    fn get_keys(&self) -> Result<Vec<String>, DatabaseError>;
    fn get_derived_keys(&self) -> Result<Vec<String>, DatabaseError>;
    fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, DatabaseError>;
    fn get_derived_value(&self, key: &String) -> Result<String, DatabaseError>;
    fn get_derived_keys_in_order(&self) -> Result<Vec<String>, DatabaseError>;
    fn get_commitment(&self, epoch: &u64) -> Result<String, DatabaseError>;
    fn get_proof(&self, id: &String) -> Result<String, DatabaseError>;
    fn get_proofs_in_epoch(&self, epoch: &u64) -> Result<Vec<Proof>, DatabaseError>;
    fn get_epoch(&self) -> Result<u64, DatabaseError>;
    fn get_epoch_operation(&self) -> Result<u64, DatabaseError>;
    fn set_epoch(&self, epoch: &u64) -> Result<(), DatabaseError>;
    fn reset_epoch_operation_counter(&self) -> Result<(), DatabaseError>;
    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &Vec<ChainEntry>,
    ) -> Result<(), DeimosError>;
    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> Result<(), DatabaseError>;
    fn get_epochs(&self) -> Result<Vec<u64>, DeimosError>;
    fn increment_epoch_operation(&self) -> Result<u64, DatabaseError>;
    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &String,
        proofs: &String,
    ) -> Result<(), DatabaseError>;
    fn add_commitment(&self, epoch: &u64, commitment: &String) -> Result<(), DatabaseError>;
    fn initialize_derived_dict(&self) -> Result<(), DatabaseError>;
    fn flush_database(&self) -> Result<(), DatabaseError>;
}
