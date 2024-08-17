pub mod batch;
pub mod insert;
pub mod update;
pub mod utils;

// #[cfg(test)]
// mod tests {
//     use crate::nova::batch::{Hash, MerkleProofStepCircuit, UnifiedProofStep};
//     use arecibo::{
//         provider::{Bn256Engine, GrumpkinEngine},
//         traits::circuit::StepCircuit,
//     };
//     use arecibo::{
//         traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
//         PublicParams, RecursiveSNARK,
//     };
//     use bellpepper_core::{num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem};
//     use ff::PrimeField;
//     use indexed_merkle_tree::{node::Node, sha256_mod, tree::IndexedMerkleTree, tree::Proof};

//     type E1 = Bn256Engine;
//     type E2 = GrumpkinEngine;

//     type C1 = MerkleProofStepCircuit<<E1 as Engine>::Scalar>;
//     type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

//     fn debug_circuit(circuit: &C1, z_in: &[<E1 as Engine>::Scalar]) {
//         let mut cs = TestConstraintSystem::<<E1 as Engine>::Scalar>::new();

//         let z: Vec<AllocatedNum<<E1 as Engine>::Scalar>> = z_in
//             .iter()
//             .enumerate()
//             .map(|(i, &value)| {
//                 AllocatedNum::alloc(&mut cs.namespace(|| format!("input {}", i)), || Ok(value))
//                     .expect("failed to allocate input")
//             })
//             .collect();

//         circuit.synthesize(&mut cs, &z).expect("synthesis failed");

//         println!("Constraint System:");
//         println!("{}", cs.pretty_print());

//         if !cs.is_satisfied() {
//             println!("Constraint system not satisfied!");
//             for (i, constraint) in cs.which_is_unsatisfied().iter().enumerate() {
//                 println!("Unsatisfied Constraint {}: {:?}", i, constraint);
//             }
//         } else {
//             println!("All constraints satisfied.");
//         }

//         assert!(cs.is_satisfied(), "Constraints not satisfied");
//     }

//     fn create_public_params() -> PublicParams<E1, E2, C1, C2> {
//         let mut tree = IndexedMerkleTree::new_with_size(4).unwrap();
//         let test_label = sha256_mod(b"test");
//         let test_value = sha256_mod(b"value");
//         let mut test_node = Node::new_leaf(true, test_label, test_value, Node::TAIL);

//         let test_proof = tree.insert_node(&mut test_node).unwrap();
//         let test_circuit = MerkleProofStepCircuit::from_proof(Proof::Insert(test_proof))[0].clone();

//         let circuit_primary = test_circuit;
//         let circuit_secondary = TrivialCircuit::default();

//         PublicParams::<E1, E2, C1, C2>::setup(
//             &circuit_primary,
//             &circuit_secondary,
//             &*default_ck_hint(),
//             &*default_ck_hint(),
//         )
//         .unwrap()
//     }

//     #[test]
//     fn test_nova() {
//         let mut tree = IndexedMerkleTree::new_with_size(4).unwrap();
//         let initial_commitment = Hash::new(tree.get_commitment().unwrap())
//             .to_scalar()
//             .unwrap();

//         // create three nodes to insert
//         let ryan = sha256_mod(b"Ryan");
//         let ford = sha256_mod(b"Ford");
//         let sebastian = sha256_mod(b"Sebastian");
//         let pusch = sha256_mod(b"Pusch");
//         let ethan = sha256_mod(b"Ethan");
//         let triple_zero = sha256_mod(b"000");

//         let mut ryans_node = Node::new_leaf(true, ryan, ford, Node::TAIL);
//         let mut sebastians_node = Node::new_leaf(true, sebastian, pusch, Node::TAIL);
//         let mut ethans_node = Node::new_leaf(true, ethan, triple_zero, Node::TAIL);

//         // generate proofs for the three nodes
//         let first_insert_proof = tree.insert_node(&mut ryans_node).unwrap();
//         let second_insert_proof = tree.insert_node(&mut sebastians_node).unwrap();
//         let third_insert_proof = tree.insert_node(&mut ethans_node).unwrap();

//         // create zkSNARKs for the three proofs
//         let first_insert_zk_snark = Proof::Insert(first_insert_proof);
//         let second_insert_zk_snark = Proof::Insert(second_insert_proof);
//         let third_insert_zk_snark = Proof::Insert(third_insert_proof);

//         let proofs = vec![
//             first_insert_zk_snark,
//             second_insert_zk_snark,
//             third_insert_zk_snark,
//         ];

//         let circuits: Vec<C1> = proofs
//             .into_iter()
//             .flat_map(MerkleProofStepCircuit::from_proof)
//             .collect();

//         println!("Creating public params...");
//         let pp = create_public_params();
//         println!("Created public params.");

//         let initial_primary_inputs = vec![
//             initial_commitment,
//             <E1 as Engine>::Scalar::zero(), // initial existing node label
//             <E1 as Engine>::Scalar::zero(), // initial missing node label
//         ];

//         let secondary_circuit = TrivialCircuit::default();

//         println!("Creating recursive snark...");
//         let recursive_snark_result = RecursiveSNARK::new(
//             &pp,
//             &circuits[0],
//             &secondary_circuit,
//             &initial_primary_inputs,
//             &[<E2 as Engine>::Scalar::from(2u64)],
//         );

//         let mut z1_scalars = initial_primary_inputs;
//         let mut z2_scalars = [<E2 as Engine>::Scalar::from(2u64)];

//         match recursive_snark_result {
//             Ok(mut recursive_snark) => {
//                 println!("Created recursive snark successfully.");

//                 for (i, circuit) in circuits.iter().enumerate() {
//                     println!("Step: {i}");

//                     debug_circuit(circuit, &z1_scalars);

//                     let prove_result = recursive_snark.prove_step(&pp, circuit, &secondary_circuit);

//                     match prove_result {
//                         Ok(_) => {
//                             println!("Prove step {i} succeeded");
//                         }
//                         Err(e) => {
//                             println!("Prove step {i} failed with error: {:?}", e);
//                             panic!("Test failed at prove step {i}");
//                         }
//                     }

//                     let verify_result =
//                         recursive_snark.verify(&pp, i + 1, &z1_scalars, &z2_scalars);

//                     match verify_result {
//                         Ok(_) => {
//                             println!("Verify step {i} succeeded")
//                         }
//                         Err(e) => {
//                             println!("Verify step {i} failed with error: {:?}", e);
//                             panic!("Test failed at verify step {i}");
//                         }
//                     }
//                 }
//             }
//             Err(e) => {
//                 println!("Failed to create recursive snark. Error: {:?}", e);
//                 panic!("Test failed during recursive snark creation");
//             }
//         }
//     }
// }
