use crate::{circuits::utils::hash_to_scalar, common::HashchainEntry, error::GeneralError};
use anyhow::Result;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bls12_381::Scalar;
use indexed_merkle_tree::sha256_mod;

#[derive(Clone)]
pub struct HashChainEntryCircuit {
    pub value: Scalar,
    pub chain: Vec<Scalar>,
}

impl HashChainEntryCircuit {
    pub fn create(
        value: &str,
        hashchain: Vec<HashchainEntry>,
    ) -> Result<HashChainEntryCircuit, GeneralError> {
        // hash the clear text and parse it to scalar
        let hashed_value = sha256_mod(value.as_bytes());
        let parsed_value = hash_to_scalar(&hashed_value)?;
        let mut parsed_hashchain: Vec<Scalar> = vec![];
        for entry in hashchain {
            parsed_hashchain.push(hash_to_scalar(&sha256_mod(
                entry.operation.value().as_bytes(),
            ))?)
        }
        Ok(HashChainEntryCircuit {
            value: parsed_value,
            chain: parsed_hashchain,
        })
    }

    pub fn create_public_parameter(value: &str) -> Result<Scalar, GeneralError> {
        let hashed_value = sha256_mod(value.as_bytes());
        hash_to_scalar(&hashed_value)
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
