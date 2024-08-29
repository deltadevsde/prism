use crate::{
    nova::utils::{next_rom_index_and_pc, Digest},
    tree::{Hasher, InsertProof, NonMembershipProof},
};
use anyhow::Result;
use arecibo::supernova::StepCircuit;
use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use jmt::proof::UpdateMerkleProof;
use std::marker::PhantomData;

#[derive(Clone)]
struct InsertProofCircuit<Scalar: PrimeField> {
    proof: InsertProof,
    _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> InsertProofCircuit<Scalar> {
    pub fn new(proof: InsertProof) -> Self {
        Self {
            proof,
            _p: PhantomData,
        }
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> StepCircuit<Scalar> for InsertProofCircuit<Scalar> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<Scalar>>,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<(Option<AllocatedNum<Scalar>>, Vec<AllocatedNum<Scalar>>), SynthesisError> {
        let mut z_out: Vec<AllocatedNum<Scalar>> = Vec::new();

        // Allocate the old root
        let old_root = AllocatedNum::alloc(cs.namespace(|| "old_root"), || {
            Ok(Digest::new(self.proof.non_membership_proof.root)
                .to_scalar()
                .map_err(|_| SynthesisError::Unsatisfiable)?)
        })?;

        // Allocate the new root
        let new_root = AllocatedNum::alloc(cs.namespace(|| "new_root"), || {
            Ok(Digest::new(self.proof.new_root)
                .to_scalar()
                .map_err(|_| SynthesisError::Unsatisfiable)?)
        })?;

        // Allocate the key
        let key_bits = allocate_bits_to_binary_number(
            cs.namespace(|| "key"),
            Some(self.proof.non_membership_proof.key.0.to_vec()),
        )?;

        // Allocate the value
        let value_bytes = self.proof.value.to_bytes();
        let mut value_bits = Vec::new();

        for (byte_idx, &byte) in value_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = AllocatedBit::alloc(
                    cs.namespace(|| format!("value bit {}.{}", byte_idx, bit_idx)),
                    Some((byte >> bit_idx) & 1 == 1),
                )?;
                value_bits.push(Boolean::from(bit));
            }
        }

        // Hash the key and value
        let leaf_hash = sha256(
            cs.namespace(|| "leaf_hash"),
            &[key_bits.clone(), value_bits].concat(),
        )
        .map_err(|e| SynthesisError::Unsatisfiable)?;

        // Verify the non-membership proof
        verify_non_membership_proof(
            cs.namespace(|| "non_membership_proof"),
            &self.proof.non_membership_proof,
            &old_root,
            &key_bits,
        )?;

        // Verify the membership proof (update)
        verify_membership_proof(
            cs.namespace(|| "membership_proof"),
            &self.proof.membership_proof,
            &old_root,
            &new_root,
            &key_bits,
            &leaf_hash,
        )?;

        z_out.push(new_root);

        let new_pc = match pc {
            Some(old_pc) => {
                let new_pc =
                    AllocatedNum::alloc(cs.namespace(|| "new_pc"), || match old_pc.get_value() {
                        Some(v) => Ok(v + Scalar::from(1)),
                        None => Err(SynthesisError::AssignmentMissing),
                    })?;

                // Enforce that new_pc = old_pc + 1
                cs.enforce(
                    || "new_pc = old_pc + 1",
                    |lc| lc + old_pc.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + new_pc.get_variable(),
                );

                Some(new_pc)
            }
            None => None,
        };

        Ok((new_pc, z_out))
    }

    fn circuit_index(&self) -> usize {
        0
    }
}

fn allocate_bits_to_binary_number<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: Option<Vec<u8>>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let bits = value
        .map(|bytes| {
            bytes
                .iter()
                .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![false; 256]);

    let mut result = Vec::new();
    for (i, &bit) in bits.iter().enumerate() {
        let allocated_bit = AllocatedBit::alloc(cs.namespace(|| format!("bit {}", i)), Some(bit))?;
        result.push(Boolean::from(allocated_bit));
    }
    Ok(result)
}

fn verify_non_membership_proof<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    proof: &NonMembershipProof,
    root: &[Boolean],
    key: &[Boolean],
) -> Result<(), SynthesisError> {
    // 1. Hash the key
    let key_hash = sha256(cs.namespace(|| "hash key"), key)?;

    // 2. Traverse the Merkle path
    let mut current = key_hash;
    for (i, sibling) in proof.proof.siblings().iter().enumerate() {
        let sibling_bits = allocate_bits_to_binary_number(
            cs.namespace(|| format!("sibling bits {}", i)),
            Some(sibling.to_vec()),
        )?;

        let (left, right) = if *is_left {
            (sibling_bits, current)
        } else {
            (current, sibling_bits)
        };

        current = sha256(
            cs.namespace(|| format!("hash node {}", i)),
            &[left, right].concat(),
        )?;
    }

    // 3. Check that the computed root does not match the given root
    for (i, (computed_bit, given_bit)) in current.iter().zip(root.iter()).enumerate() {
        Boolean::enforce_not_equal(
            cs.namespace(|| format!("root bit {} should not be equal", i)),
            computed_bit,
            given_bit,
        )?;
    }

    Ok(())
}

fn verify_membership_proof<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    proof: &UpdateMerkleProof<Hasher>,
    old_root: &AllocatedNum<Scalar>,
    new_root: &AllocatedNum<Scalar>,
    key: &[Boolean],
    leaf_hash: &[Boolean],
) -> Result<(), SynthesisError> {
    // lfg implementing the logic to verify the membership proof
    Ok(())
}

#[derive(Clone)]
pub struct InsertCircuit<F> {
    pub insertion_proof: InsertProof,
    rom_size: usize,
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> InsertCircuit<F> {
    pub fn new(insertion_proof: InsertProof, rom_size: usize) -> Self {
        Self {
            insertion_proof,
            rom_size,
            _phantom: PhantomData,
        }
    }
}

impl<F> StepCircuit<F> for InsertCircuit<F>
where
    F: PrimeField,
{
    fn arity(&self) -> usize {
        2 + self.rom_size // old_root + rom_index + rom[].len()
    }

    fn circuit_index(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<F>>,
        z: &[AllocatedNum<F>],
    ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        let old_root = &z[0];
        let rom_index = &z[1];
        let allocated_rom = &z[2..];

        let pc = pc.ok_or(SynthesisError::AssignmentMissing)?;

        let (rom_index_next, pc_next) = next_rom_index_and_pc(
            &mut cs.namespace(|| "next and rom_index and pc"),
            rom_index,
            allocated_rom,
            pc,
        )?;

        let pre_insertion_scalar = Digest::new(self.insertion_proof.non_membership_proof.root)
            .to_scalar()
            .map_err(|_| SynthesisError::Unsatisfiable);
        let pre_insertion_root =
            AllocatedNum::alloc(cs.namespace(|| "pre_insertion_root"), || {
                pre_insertion_scalar
            })?;
        let new_scalar = Digest::new(self.insertion_proof.new_root)
            .to_scalar()
            .map_err(|_| SynthesisError::Unsatisfiable);
        let new_root = AllocatedNum::alloc(cs.namespace(|| "new_root"), || new_scalar)?;

        cs.enforce(
            || "z0 == pre_insertion_root",
            |lc| lc + old_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + pre_insertion_root.get_variable(),
        );
        // TODO: bellpepper merkle proof gadget
        self.insertion_proof
            .verify()
            .map_err(|_| SynthesisError::Unsatisfiable)?;

        let mut z_next = vec![new_root];
        z_next.push(rom_index_next);
        z_next.extend(z[2..].iter().cloned());

        Ok((Some(pc_next), z_next))
    }
}
