// use bellpepper_core::ConstraintSystem;

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
