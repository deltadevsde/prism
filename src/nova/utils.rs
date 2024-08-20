// use bellpepper_core::ConstraintSystem;
use anyhow::Result;
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;
use itertools::Itertools as _;
use jmt::RootHash;
use std::marker::PhantomData;

use crate::tree;

pub struct Digest<Scalar: PrimeField> {
    digest: tree::Digest,
    _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField> Digest<Scalar> {
    pub fn new(digest: tree::Digest) -> Self {
        Self {
            digest,
            _p: PhantomData,
        }
    }

    pub fn from_root_hash(root_hash: RootHash) -> Self {
        Self::new(root_hash.into())
    }

    // uses [`PrimeField::from_u128`] for inspiration. If the field element's capacity is not enough to hold the hash,
    pub fn to_scalar(&self) -> Result<Scalar> {
        let bytes = self.digest.as_ref();

        // Convert the 32 bytes to two u128 values
        let lower = u128::from_le_bytes(bytes[0..16].try_into()?);
        let upper = u128::from_le_bytes(bytes[16..32].try_into()?);

        let mut tmp = Scalar::from_u128(upper);
        for _ in 0..128 {
            tmp = tmp.double();
        }
        Ok(tmp + Scalar::from_u128(lower))
    }
}

pub struct Hash<Scalar: PrimeField> {
    hash: indexed_merkle_tree::Hash,
    _p: PhantomData<Scalar>,
}

pub fn next_rom_index_and_pc<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    rom_index: &AllocatedNum<F>,
    allocated_rom: &[AllocatedNum<F>],
    pc: &AllocatedNum<F>,
) -> Result<(AllocatedNum<F>, AllocatedNum<F>), SynthesisError> {
    // Compute a selector for the current rom_index in allocated_rom
    let current_rom_selector = get_selector_vec_from_index(
        cs.namespace(|| "rom selector"),
        rom_index,
        allocated_rom.len(),
    )?;

    // Enforce that allocated_rom[rom_index] = pc
    for (rom, bit) in allocated_rom.iter().zip_eq(current_rom_selector.iter()) {
        // if bit = 1, then rom = pc
        // bit * (rom - pc) = 0
        cs.enforce(
            || "enforce bit = 1 => rom = pc",
            |lc| lc + &bit.lc(CS::one(), F::ONE),
            |lc| lc + rom.get_variable() - pc.get_variable(),
            |lc| lc,
        );
    }

    // Get the index of the current rom, or the index of the invalid rom if no match
    let current_rom_index = current_rom_selector
        .iter()
        .position(|bit| bit.get_value().is_some_and(|v| v))
        .unwrap_or_default();
    let next_rom_index = current_rom_index + 1;

    let rom_index_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next rom index"), || {
        F::from(next_rom_index as u64)
    });
    cs.enforce(
        || " rom_index + 1 - next_rom_index_num = 0",
        |lc| lc,
        |lc| lc,
        |lc| lc + rom_index.get_variable() + CS::one() - rom_index_next.get_variable(),
    );

    // Allocate the next pc without checking.
    // The next iteration will check whether the next pc is valid.
    let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next pc"), || {
        allocated_rom
            .get(next_rom_index)
            .and_then(|v| v.get_value())
            .unwrap_or(-F::ONE)
    });

    Ok((rom_index_next, pc_next))
}

/// Compute a selector vector `s` of size `num_indices`, such that
/// `s[i] == 1` if i == `target_index` and 0 otherwise.
pub fn get_selector_vec_from_index<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    target_index: &AllocatedNum<F>,
    num_indices: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
    assert_ne!(num_indices, 0);

    // Compute the selector vector non-deterministically
    let selector = (0..num_indices)
        .map(|idx| {
            // b <- idx == target_index
            Ok(Boolean::Is(AllocatedBit::alloc(
                cs.namespace(|| format!("allocate s_{:?}", idx)),
                target_index.get_value().map(|v| v == F::from(idx as u64)),
            )?))
        })
        .collect::<Result<Vec<Boolean>, SynthesisError>>()?;

    // Enforce ∑ selector[i] = 1
    {
        let selected_sum = selector.iter().fold(LinearCombination::zero(), |lc, bit| {
            lc + &bit.lc(CS::one(), F::ONE)
        });
        cs.enforce(
            || "exactly-one-selection",
            |_| selected_sum,
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }

    // Enforce `target_index - ∑ i * selector[i] = 0``
    {
        let selected_value = selector
            .iter()
            .enumerate()
            .fold(LinearCombination::zero(), |lc, (i, bit)| {
                lc + &bit.lc(CS::one(), F::from(i as u64))
            });
        cs.enforce(
            || "target_index - ∑ i * selector[i] = 0",
            |lc| lc,
            |lc| lc,
            |lc| lc + target_index.get_variable() - &selected_value,
        );
    }

    Ok(selector)
}

// pub(crate) fn prove_update<CS: ConstraintSystem<Scalar>>(
//     cs: &mut CS,
//     old_root: Scalar,
//     old_path: &[Node],
//     new_root: Scalar,
//     new_path: &[Node],
// ) -> Result<Scalar, SynthesisError> {
//     let root_with_old_pointer =
//         cs.alloc(|| "first update root with old pointer", || Ok(old_root))?;
//     let root_with_new_pointer =
//         cs.alloc(|| "first update root with new pointer", || Ok(new_root))?;

//     // update the root hash for old and new path
//     let recalculated_root_with_old_pointer =
//         recalculate_hash_as_scalar(old_path).map_err(|_| SynthesisError::Unsatisfiable)?;
//     let recalculated_root_with_new_pointer =
//         recalculate_hash_as_scalar(new_path).map_err(|_| SynthesisError::Unsatisfiable)?;

//     let allocated_recalculated_root_with_old_pointer = cs.alloc(
//         || "recalculated first update proof old root",
//         || Ok(recalculated_root_with_old_pointer),
//     )?;
//     let allocated_recalculated_root_with_new_pointer = cs.alloc(
//         || "recalculated first update proof new root",
//         || Ok(recalculated_root_with_new_pointer),
//     )?;

//     // Check if the resulting hash is the root hash of the old tree
//     // allocated_recalculated_root_with_old_pointer * (1) = root_with_old_pointer
//     cs.enforce(
//         || "first update old root equality",
//         |lc| lc + allocated_recalculated_root_with_old_pointer,
//         |lc| lc + CS::one(),
//         |lc| lc + root_with_old_pointer,
//     );

//     // Check that the resulting hash is the root hash of the new tree.
//     // allocated_recalculated_root_with_new_pointer * (1) = root_with_new_pointer
//     cs.enforce(
//         || "first update new root equality",
//         |lc| lc + allocated_recalculated_root_with_new_pointer,
//         |lc| lc + CS::one(),
//         |lc| lc + root_with_new_pointer,
//     );

//     Ok(recalculated_root_with_new_pointer)
// }
