pub mod batch;

#[cfg(test)]
mod tests {
    use crate::nova::batch::MerkleProofStepCircuit;
    use indexed_merkle_tree::{node::Node, sha256_mod, tree::IndexedMerkleTree, tree::Proof};
    use nova_snark::{
        provider::{Bn256EngineKZG, GrumpkinEngine},
        traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
        PublicParams, RecursiveSNARK,
    };

    type E1 = Bn256EngineKZG;
    type E2 = GrumpkinEngine;

    type C1 = MerkleProofStepCircuit<<E1 as Engine>::Scalar>;
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

    fn create_public_params() -> PublicParams<E1, E2, C1, C2> {
        let mut tree = IndexedMerkleTree::new_with_size(4).unwrap();
        let test_label = sha256_mod(b"test");
        let test_value = sha256_mod(b"value");
        let mut test_node = Node::new_leaf(true, test_label, test_value, Node::TAIL);

        let test_proof = tree.insert_node(&mut test_node).unwrap();
        let test_circuit = MerkleProofStepCircuit::from_proof(Proof::Insert(test_proof))[0].clone();

        let circuit_primary = test_circuit;
        let circuit_secondary = TrivialCircuit::default();

        PublicParams::<E1, E2, C1, C2>::setup(
            &circuit_primary,
            &circuit_secondary,
            &*default_ck_hint(),
            &*default_ck_hint(),
        )
        .unwrap()
    }

    #[test]
    fn test_nova() {
        let mut tree = IndexedMerkleTree::new_with_size(4).unwrap();

        // create three nodes to insert
        let ryan = sha256_mod(b"Ryan");
        let ford = sha256_mod(b"Ford");
        let sebastian = sha256_mod(b"Sebastian");
        let pusch = sha256_mod(b"Pusch");
        let ethan = sha256_mod(b"Ethan");
        let triple_zero = sha256_mod(b"000");

        let mut ryans_node = Node::new_leaf(true, ryan, ford, Node::TAIL);
        let mut sebastians_node = Node::new_leaf(true, sebastian, pusch, Node::TAIL);
        let mut ethans_node = Node::new_leaf(true, ethan, triple_zero, Node::TAIL);

        // generate proofs for the three nodes
        let first_insert_proof = tree.insert_node(&mut ryans_node).unwrap();
        let second_insert_proof = tree.insert_node(&mut sebastians_node).unwrap();
        let third_insert_proof = tree.insert_node(&mut ethans_node).unwrap();

        // create zkSNARKs for the three proofs
        let first_insert_zk_snark = Proof::Insert(first_insert_proof);
        let second_insert_zk_snark = Proof::Insert(second_insert_proof);
        let third_insert_zk_snark = Proof::Insert(third_insert_proof);

        let proofs = vec![
            first_insert_zk_snark,
            second_insert_zk_snark,
            third_insert_zk_snark,
        ];

        let circuits: Vec<C1> = proofs
            .into_iter()
            .flat_map(MerkleProofStepCircuit::from_proof)
            .collect();

        println!("Creating public params...");
        let pp = create_public_params();
        println!("Created public params.");

        println!("Creating recursive snark...");
        let initial_primary_inputs = vec![
            <E1 as Engine>::Scalar::zero(), // initial root
            <E1 as Engine>::Scalar::zero(), // initial existing node label
            <E1 as Engine>::Scalar::zero(), // initial missing node label
        ];

        let (initial_circuit, next_steps) = circuits.split_first().unwrap();

        let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> = RecursiveSNARK::new(
            &pp,
            initial_circuit,
            &TrivialCircuit::default(),
            &initial_primary_inputs,
            &[<E2 as Engine>::Scalar::from(2u64)],
        )
        .unwrap();
        println!("Created recursive snark.");

        for (i, circuit) in next_steps.iter().enumerate() {
            println!("Added proof {i} to recursive snark");
            recursive_snark.prove_step(&pp, circuit, &TrivialCircuit::default());
            // assert!(res.is_ok());

            // let res = recursive_snark.verify(
            //     &pp,
            //     i + 1,
            //     &[<E1 as Engine>::Scalar::from(3u64)],
            //     &[<E2 as Engine>::Scalar::from(2u64)],
            // );
            // assert!(res.is_ok());
        }

        // Add assertions to check the final state if needed
        // For example, you might want to check if the final root matches the expected value
        // assert_eq!(final_root, expected_root);
    }
}
