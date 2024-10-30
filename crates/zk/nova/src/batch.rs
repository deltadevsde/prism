use super::{insert::InsertCircuit, update::UpdateCircuit};
use arecibo::{
    supernova::{StepCircuit, TrivialSecondaryCircuit},
    traits::{CurveCycleEquipped, Dual, Engine},
};
use ff::{PrimeField, PrimeFieldBits};
use prism_common::tree::{InsertProof, UpdateProof};
use std::cell::RefCell;

#[derive(Clone)]
pub struct EpochCircuitSequence<E1>
where
    E1: CurveCycleEquipped,
{
    insert_circuits: Vec<EpochCircuit<E1::Scalar>>,
    update_circuits: Vec<EpochCircuit<E1::Scalar>>,
    rom: Vec<usize>,
    insert_index: RefCell<usize>,
    update_index: RefCell<usize>,
}

impl<E1> EpochCircuitSequence<E1>
where
    E1: CurveCycleEquipped,
{
    pub fn new(operations: Vec<(usize, EpochCircuit<E1::Scalar>)>) -> Self {
        let rom = operations.iter().map(|(op, _)| *op).collect();
        let (insert_circuits, update_circuits): (Vec<_>, Vec<_>) = operations
            .into_iter()
            .map(|(_, circuit)| circuit)
            .partition(|circuit| matches!(circuit, EpochCircuit::Insert(_)));

        Self {
            insert_circuits,
            update_circuits,
            rom,
            insert_index: RefCell::new(0),
            update_index: RefCell::new(0),
        }
    }

    pub fn reset_indices(&self) {
        *self.insert_index.borrow_mut() = 0;
        *self.update_index.borrow_mut() = 0;
    }
}

impl<E1> arecibo::supernova::NonUniformCircuit<E1> for EpochCircuitSequence<E1>
where
    E1: CurveCycleEquipped,
{
    type C1 = EpochCircuit<E1::Scalar>;
    type C2 = TrivialSecondaryCircuit<<Dual<E1> as Engine>::Scalar>;

    fn num_circuits(&self) -> usize {
        self.insert_circuits.len() + self.update_circuits.len()
    }

    fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
        let (circuits, index) = if circuit_index == 0 {
            (&self.insert_circuits, &self.insert_index)
        } else {
            (&self.update_circuits, &self.update_index)
        };

        let mut current_index = index.borrow_mut();

        if *current_index >= circuits.len() {
            *current_index = 0;
        }

        let circuit = circuits[*current_index].clone();
        *current_index += 1;
        circuit
    }

    fn secondary_circuit(&self) -> Self::C2 {
        TrivialSecondaryCircuit::default()
    }

    fn initial_circuit_index(&self) -> usize {
        self.rom[0]
    }
}

#[derive(Clone)]
pub enum EpochCircuit<F: PrimeField + PrimeFieldBits> {
    Insert(InsertCircuit<F>),
    Update(UpdateCircuit<F>),
}

impl<F: PrimeField + PrimeFieldBits> EpochCircuit<F> {
    pub fn new_insert(insertion_proof: InsertProof, rom_size: usize) -> Self {
        Self::Insert(InsertCircuit::new(insertion_proof, rom_size))
    }

    pub fn new_update(update_proof: UpdateProof, rom_size: usize) -> Self {
        Self::Update(UpdateCircuit::new(update_proof, rom_size))
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for EpochCircuit<F> {
    fn arity(&self) -> usize {
        match self {
            Self::Insert(x) => x.arity(),
            Self::Update(x) => x.arity(),
        }
    }

    fn synthesize<CS: bellpepper_core::ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        pc: Option<&bellpepper_core::num::AllocatedNum<F>>,
        z: &[bellpepper_core::num::AllocatedNum<F>],
    ) -> Result<
        (
            Option<bellpepper_core::num::AllocatedNum<F>>,
            Vec<bellpepper_core::num::AllocatedNum<F>>,
        ),
        bellpepper_core::SynthesisError,
    > {
        match self {
            Self::Insert(x) => x.synthesize(cs, pc, z),
            Self::Update(x) => x.synthesize(cs, pc, z),
        }
    }

    fn circuit_index(&self) -> usize {
        match self {
            Self::Insert(x) => x.circuit_index(),
            Self::Update(x) => x.circuit_index(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::Digest as NovaDigest;
    use arecibo::{
        provider::PallasEngine,
        supernova::{NonUniformCircuit, PublicParams, RecursiveSNARK},
        traits::snark::default_ck_hint,
    };
    use ff::Field;
    use prism_common::test_utils::{create_random_insert, create_random_update, TestTreeState};
    use rand::{rngs::StdRng, SeedableRng};

    // ignored because proving in CI is slow
    #[ignore]
    #[test]
    fn test_recursive_epoch_circuit_proof() {
        type E1 = PallasEngine;

        let mut state = TestTreeState::new();
        let mut rng = StdRng::from_entropy();

        let initial_commitment: <E1 as Engine>::Scalar =
            NovaDigest::from_root_hash(state.tree.get_commitment().unwrap().into())
                .to_scalar()
                .unwrap();

        let operations = vec![
            (
                0,
                EpochCircuit::new_insert(create_random_insert(&mut state, &mut rng), 2),
            ),
            (
                1,
                EpochCircuit::new_update(create_random_update(&mut state, &mut rng), 2),
            ),
            // (
            //     0,
            //     EpochCircuit::new_insert(create_random_insert(&mut state, &mut rng), 3),
            // ),
            // (
            //     1,
            //     EpochCircuit::new_update(create_random_update(&mut state, &mut rng), 4),
            // ),
        ];

        let circuit_sequence = EpochCircuitSequence::<E1>::new(operations);

        let pp = PublicParams::setup(&circuit_sequence, &*default_ck_hint(), &*default_ck_hint());

        let mut z0_primary = vec![initial_commitment]; // Initial root
        z0_primary.push(<E1 as Engine>::Scalar::ZERO); // Initial ROM index
        z0_primary
            .extend(circuit_sequence.rom.iter().map(|&x| <E1 as Engine>::Scalar::from(x as u64)));

        let z0_secondary = vec![<<Dual<E1> as Engine>::Scalar>::ONE];

        let mut recursive_snark_option: Option<RecursiveSNARK<E1>> = None;
        circuit_sequence.reset_indices();
        println!("ROM sequence: {:?}", circuit_sequence.rom);
        for &op_code in circuit_sequence.rom.iter() {
            println!("Processing operation: {}", op_code);
            let primary_circuit = circuit_sequence.primary_circuit(op_code);
            let secondary_circuit = circuit_sequence.secondary_circuit();

            let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
                RecursiveSNARK::new(
                    &pp,
                    &circuit_sequence,
                    &primary_circuit,
                    &secondary_circuit,
                    &z0_primary,
                    &z0_secondary,
                )
                .unwrap()
            });

            recursive_snark.prove_step(&pp, &primary_circuit, &secondary_circuit).unwrap();

            recursive_snark.verify(&pp, &z0_primary, &z0_secondary).unwrap();

            recursive_snark_option = Some(recursive_snark)
        }

        assert!(recursive_snark_option.is_some());

        let recursive_snark = recursive_snark_option.unwrap();

        assert!(recursive_snark.verify(&pp, &z0_primary, &z0_secondary).is_ok());

        // Additional assertions
        let zi_primary = recursive_snark.zi_primary();
        println!("Final primary state: {:?}", zi_primary);

        assert_eq!(
            zi_primary.len(),
            z0_primary.len(),
            "Primary state vector length should remain constant"
        );

        let final_commitment: <E1 as Engine>::Scalar =
            NovaDigest::new(state.tree.get_commitment().unwrap()).to_scalar().unwrap();

        assert_eq!(
            zi_primary[0], final_commitment,
            "Final commitment should match the tree state"
        );
    }
}
