use crate::{
    nova::utils::{
        allocate_bits_to_binary_number, next_rom_index_and_pc, verify_membership_proof, Digest,
    },
    tree::InsertProof,
};
use anyhow::Result;
use arecibo::supernova::StepCircuit;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{PrimeField, PrimeFieldBits};
use sha2::Sha256;

#[derive(Clone)]
pub struct InsertCircuit<F> {
    pub proof: InsertProof,
    rom_size: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<Scalar: PrimeField + PrimeFieldBits> InsertCircuit<Scalar> {
    pub fn new(proof: InsertProof, rom_size: usize) -> Self {
        Self {
            proof,
            rom_size,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> StepCircuit<Scalar> for InsertCircuit<Scalar> {
    fn arity(&self) -> usize {
        2 + self.rom_size // old_root + rom_index + rom[].len()
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<Scalar>>,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<(Option<AllocatedNum<Scalar>>, Vec<AllocatedNum<Scalar>>), SynthesisError> {
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

        let pre_insertion_scalar = Digest::new(self.proof.non_membership_proof.root)
            .to_scalar()
            .map_err(|_| SynthesisError::Unsatisfiable);
        let pre_insertion_root =
            AllocatedNum::alloc(cs.namespace(|| "pre_insertion_root"), || {
                pre_insertion_scalar
            })?;

        cs.enforce(
            || "z0 == pre_insertion_root",
            |lc| lc + old_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + pre_insertion_root.get_variable(),
        );

        // Allocate the new root
        let new_root = AllocatedNum::alloc(cs.namespace(|| "new_root"), || {
            Digest::new(self.proof.new_root)
                .to_scalar()
                .map_err(|_| SynthesisError::Unsatisfiable)
        })?;

        let new_root_bits =
            allocate_bits_to_binary_number(cs, self.proof.membership_proof.root_hash().0.to_vec())?;

        self.proof
            .verify()
            .map_err(|_| SynthesisError::Unsatisfiable)?;

        // Verify the non-membership proof
        // verify_non_membership_proof(
        //     cs.namespace(|| "non_membership_proof"),
        //     &self.proof.non_membership_proof,
        //     &old_root,
        //     &key_bits,
        // )?;

        let leaf = &self
            .proof
            .membership_proof
            .leaf()
            .ok_or(SynthesisError::AssignmentMissing)?;

        verify_membership_proof(cs, &self.proof.membership_proof, &new_root_bits, *leaf)?;

        let mut z_next = vec![new_root];
        z_next.push(rom_index_next);
        z_next.extend(z[2..].iter().cloned());

        Ok((Some(pc_next), z_next))
    }

    fn circuit_index(&self) -> usize {
        0
    }
}
