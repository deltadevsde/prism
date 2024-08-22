use crate::{
    nova::utils::{next_rom_index_and_pc, Digest as NovaDigest},
    tree::UpdateProof,
};
use anyhow::Result;
use arecibo::supernova::StepCircuit;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

#[derive(Clone)]
pub struct UpdateCircuit<F> {
    pub update_proof: UpdateProof,
    rom_size: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> UpdateCircuit<F> {
    pub fn new(update_proof: UpdateProof, rom_size: usize) -> Self {
        Self {
            update_proof,
            rom_size,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F> StepCircuit<F> for UpdateCircuit<F>
where
    F: PrimeField,
{
    fn arity(&self) -> usize {
        2 + self.rom_size // old_root + rom_index + rom[].len()
    }

    fn circuit_index(&self) -> usize {
        1
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
            &mut cs.namespace(|| "next rom_index and pc"),
            rom_index,
            allocated_rom,
            pc,
        )?;

        let pre_insertion_scalar = NovaDigest::from_root_hash(self.update_proof.old_root)
            .to_scalar()
            .map_err(|_| SynthesisError::Unsatisfiable);
        let pre_insertion_root =
            AllocatedNum::alloc(cs.namespace(|| "pre_insertion_root"), || {
                pre_insertion_scalar
            })?;
        let new_scalar = NovaDigest::from_root_hash(self.update_proof.new_root)
            .to_scalar()
            .map_err(|_| SynthesisError::Unsatisfiable);
        let new_root = AllocatedNum::alloc(cs.namespace(|| "new_root"), || new_scalar)?;

        cs.enforce(
            || "z0 == pre_insertion_root",
            |lc| lc + old_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + pre_insertion_root.get_variable(),
        );
        // // TODO: bellpepper merkle proof gadget
        self.update_proof
            .verify()
            .map_err(|_| SynthesisError::Unsatisfiable)?;

        let mut z_next = vec![new_root];
        z_next.push(rom_index_next);
        z_next.extend(z[2..].iter().cloned());

        Ok((Some(pc_next), z_next))
    }
}
