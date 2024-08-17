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
