use crate::common::HashchainEntry;
use anyhow::Result;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bls12_381::Scalar;
use indexed_merkle_tree::sha256_mod;

/// HashChainEntryCircuit is a circuit that verifies that a given value is present in a hashchain.
#[derive(Clone)]
pub struct HashChainEntryCircuit {
    pub value: Scalar,
    /// Represents the hashchain in the form of a vector of Scalars.
    /// Each Scalar is sha256_mod(hashchain_entry.value())
    pub chain: Vec<Scalar>,
}

impl HashChainEntryCircuit {
    pub fn create(value: &str, hashchain: Vec<HashchainEntry>) -> Result<HashChainEntryCircuit> {
        let hashed_value = sha256_mod(value.as_bytes());
        let parsed_value = hashed_value.try_into()?;
        let mut parsed_hashchain: Vec<Scalar> = vec![];
        for entry in hashchain {
            let hashed_entry_value = sha256_mod(entry.operation.value().as_bytes());
            parsed_hashchain.push(hashed_entry_value.try_into()?)
        }
        Ok(HashChainEntryCircuit {
            value: parsed_value,
            chain: parsed_hashchain,
        })
    }
}

impl Circuit<Scalar> for HashChainEntryCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if self.chain.is_empty() {
            return Err(SynthesisError::AssignmentMissing);
        }

        let provided_value = cs.alloc_input(|| "provided hashed value", || Ok(self.value))?;

        for entry in self.chain {
            if entry == self.value {
                let found_value = cs.alloc(|| "found hashed value", || Ok(entry))?;
                // found_value * (1) = provided_value
                cs.enforce(
                    || "found value check",
                    |lc| lc + found_value,
                    |lc| lc + CS::one(),
                    |lc| lc + provided_value,
                );
                return Ok(());
            }
        }
        Err(SynthesisError::Unsatisfiable)
    }
}
