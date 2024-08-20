use super::{insert::InsertCircuit, update::UpdateCircuit};
use crate::tree::{InsertProof, UpdateProof};
use arecibo::supernova::StepCircuit;
use arecibo::supernova::TrivialSecondaryCircuit;
use arecibo::traits::{CurveCycleEquipped, Dual, Engine};
use ff::PrimeField;

// Assume these functions exist
fn create_random_insert() -> InsertProof {
    unimplemented!()
}
fn create_random_update() -> UpdateProof {
    unimplemented!()
}

#[derive(Clone)]
struct EpochCircuitSequence<E1>
where
    E1: CurveCycleEquipped,
{
    circuits: Vec<EpochCircuit<E1::Scalar>>,
    rom: Vec<usize>,
}

impl<E1> EpochCircuitSequence<E1>
where
    E1: CurveCycleEquipped,
{
    pub fn new(operations: Vec<(usize, EpochCircuit<E1::Scalar>)>) -> Self {
        let rom = operations.iter().map(|(op, _)| *op).collect();
        let circuits = operations.into_iter().map(|(_, circuit)| circuit).collect();

        Self { circuits, rom }
    }
}

impl<E1> arecibo::supernova::NonUniformCircuit<E1> for EpochCircuitSequence<E1>
where
    E1: CurveCycleEquipped,
{
    type C1 = EpochCircuit<E1::Scalar>;
    type C2 = TrivialSecondaryCircuit<<Dual<E1> as Engine>::Scalar>;

    fn num_circuits(&self) -> usize {
        2 // Insert and Update
    }

    fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
        self.circuits[circuit_index].clone()
    }

    fn secondary_circuit(&self) -> Self::C2 {
        TrivialSecondaryCircuit::default()
    }

    fn initial_circuit_index(&self) -> usize {
        self.rom[0]
    }
}

#[derive(Clone)]
enum EpochCircuit<F: PrimeField> {
    Insert(InsertCircuit<F>),
    Update(UpdateCircuit<F>),
}

impl<F: PrimeField> EpochCircuit<F> {
    pub fn new_insert(insertion_proof: InsertProof, rom_size: usize) -> Self {
        Self::Insert(InsertCircuit::new(insertion_proof, rom_size))
    }

    pub fn new_update(update_proof: UpdateProof, rom_size: usize) -> Self {
        Self::Update(UpdateCircuit::new(update_proof, rom_size))
    }
}

impl<F: PrimeField> StepCircuit<F> for EpochCircuit<F> {
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
    use crate::common::Hashchain;
    use crate::nova::utils::Digest as NovaDigest;
    use crate::tree::*;
    use arecibo::provider::{PallasEngine, VestaEngine};
    use arecibo::supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit};
    use arecibo::traits::snark::default_ck_hint;
    use ff::Field;
    use jmt::mock::MockTreeStore;
    use jmt::KeyHash;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::sync::Arc;

    use std::collections::HashSet;

    struct TestTreeState {
        pub tree: KeyDirectoryTree<MockTreeStore>,
        inserted_keys: HashSet<KeyHash>,
    }

    impl TestTreeState {
        fn new() -> Self {
            let store = Arc::new(MockTreeStore::default());
            let tree = KeyDirectoryTree::new(store);
            Self {
                tree,
                inserted_keys: HashSet::new(),
            }
        }
    }

    fn create_random_insert(state: &mut TestTreeState, rng: &mut StdRng) -> InsertProof {
        loop {
            let random_string: String = (0..10)
                .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                .collect();
            let hc = Hashchain::new(random_string);
            let key = hc.get_keyhash();

            if !state.inserted_keys.contains(&key) {
                let proof = state.tree.insert(key, hc).expect("Insert should succeed");
                state.inserted_keys.insert(key);
                return proof;
            }
        }
    }

    fn create_random_update(state: &mut TestTreeState, rng: &mut StdRng) -> UpdateProof {
        if state.inserted_keys.is_empty() {
            panic!("No keys have been inserted yet. Cannot perform update.");
        }

        let key = *state
            .inserted_keys
            .iter()
            .nth(rng.gen_range(0..state.inserted_keys.len()))
            .unwrap();
        let mut hc = state.tree.get(key).unwrap().unwrap();

        let random_string: String = (0..10)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();
        hc.add(random_string)
            .expect("Adding to hashchain should succeed");

        state.tree.update(key, hc).expect("Update should succeed")
    }

    #[test]
    fn test_recursive_epoch_circuit_proof() {
        type E1 = PallasEngine;
        type E2 = VestaEngine;

        let mut state = TestTreeState::new();
        let mut rng = StdRng::from_entropy();

        let operations = vec![
            (
                0,
                EpochCircuit::new_insert(create_random_insert(&mut state, &mut rng), 4),
            ),
            (
                1,
                EpochCircuit::new_update(create_random_update(&mut state, &mut rng), 4),
            ),
            (
                0,
                EpochCircuit::new_insert(create_random_insert(&mut state, &mut rng), 4),
            ),
            (
                1,
                EpochCircuit::new_update(create_random_update(&mut state, &mut rng), 4),
            ),
        ];
        let circuit_sequence = EpochCircuitSequence::<E1>::new(operations);
        let secondary_circuit = TrivialSecondaryCircuit::<<E2 as Engine>::Scalar>::default();

        let pp = PublicParams::setup(&circuit_sequence, &*default_ck_hint(), &*default_ck_hint());

        let initial_commitment: <E1 as Engine>::Scalar =
            NovaDigest::new(state.tree.get_commitment().unwrap())
                .to_scalar()
                .unwrap();
        let mut z0_primary = vec![initial_commitment]; // Initial root
        z0_primary.push(<E1 as Engine>::Scalar::ZERO); // Initial ROM index
        z0_primary.extend(
            circuit_sequence
                .rom
                .iter()
                .map(|&x| <E1 as Engine>::Scalar::from(x as u64)),
        );
        let z0_secondary = vec![<<Dual<E1> as Engine>::Scalar>::ONE];

        // Initialize RecursiveSNARK
        let mut recursive_snark = RecursiveSNARK::<E1>::new(
            &pp,
            &circuit_sequence,
            &circuit_sequence.circuits[0],
            &secondary_circuit,
            &z0_primary,
            &z0_secondary,
        )
        .unwrap();

        // Prove steps
        for circuit in &circuit_sequence.circuits {
            recursive_snark
                .prove_step(&pp, circuit, &secondary_circuit)
                .unwrap();

            // Verify after each step
            recursive_snark
                .verify(&pp, &z0_primary, &z0_secondary)
                .unwrap();
        }

        // Final verification
        assert!(recursive_snark
            .verify(&pp, &z0_primary, &z0_secondary)
            .is_ok());

        // Additional assertions
        let zi_primary = &recursive_snark.zi_primary();

        println!("Final primary state: {:?}", zi_primary);

        assert_eq!(
            zi_primary.len(),
            z0_primary.len(),
            "Primary state vector length should remain constant"
        );

        let final_commitment: <E1 as Engine>::Scalar =
            NovaDigest::new(state.tree.get_commitment().unwrap())
                .to_scalar()
                .unwrap();
        assert_eq!(
            zi_primary[0], final_commitment,
            "Final commitment should match the tree state"
        );
    }
}
