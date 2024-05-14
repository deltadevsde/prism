/* TODO: rewrite for jolt?
#[cfg(test)]
mod tests {
    use crate::zk_snark::deserialize_proof;

    use super::*;
    use bellman::groth16;
    use bls12_381::Bls12;
    use indexed_merkle_tree::{node::Node, sha256, tree::IndexedMerkleTree};
    use rand::rngs::OsRng;

    const EMPTY_HASH: &str = Node::EMPTY_HASH;
    const TAIL: &str = Node::TAIL;

    fn build_empty_tree() -> IndexedMerkleTree {
        let active_node = Node::new_leaf(
            true,
            true,
            EMPTY_HASH.to_string(),
            EMPTY_HASH.to_string(),
            TAIL.to_string(),
        );
        let inactive_node = Node::new_leaf(
            false,
            true,
            EMPTY_HASH.to_string(),
            EMPTY_HASH.to_string(),
            TAIL.to_string(),
        );

        // build a tree with 4 nodes
        IndexedMerkleTree::new(vec![
            active_node,
            inactive_node.clone(),
            inactive_node.clone(),
            inactive_node,
        ])
        .unwrap()
    }

    #[test]
    fn test_serialize_and_deserialize_proof() {
        let mut tree = build_empty_tree();
        let prev_commitment = tree.get_commitment().unwrap();

        // create two nodes to insert
        let ryan = sha256(&"Ryan".to_string());
        let ford = sha256(&"Ford".to_string());
        let sebastian = sha256(&"Sebastian".to_string());
        let pusch = sha256(&"Pusch".to_string());
        let ryans_node = Node::new_leaf(true, true, ryan, ford, TAIL.to_string());
        let sebastians_node = Node::new_leaf(true, true, sebastian, pusch, TAIL.to_string());

        // generate proofs for the two nodes
        let first_insert_proof = tree.insert_node(&ryans_node).unwrap();
        let second_insert_proof = tree.insert_node(&sebastians_node).unwrap();

        // create zkSNARKs for the two proofs
        let first_insert_zk_snark = Proof::Insert(first_insert_proof);
        let second_insert_zk_snark = Proof::Insert(second_insert_proof);

        let proofs = vec![first_insert_zk_snark, second_insert_zk_snark];
        let current_commitment = tree.get_commitment().unwrap();

        let batched_proof =
            BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs).unwrap();

        let rng = &mut OsRng;
        let params =
            groth16::generate_random_parameters::<Bls12, _, _>(batched_proof.clone(), rng).unwrap();
        let proof = groth16::create_random_proof(batched_proof.clone(), &params, rng).unwrap();

        let serialized_proof = serialize_proof(&proof);
        let deserialized_proof_result = deserialize_proof(&serialized_proof);
        assert!(deserialized_proof_result.is_ok(), "Deserialization failed");

        let deserialized_proof = deserialized_proof_result.unwrap();
        assert_eq!(proof.a, deserialized_proof.a);
        assert_eq!(proof.b, deserialized_proof.b);
        assert_eq!(proof.c, deserialized_proof.c);
    }

    #[test]
    fn test_deserialize_invalid_proof() {
        // Erstellen Sie ein ungültiges Bls12Proof-Objekt
        let invalid_proof = Bls12Proof {
            a: "blubbubs".to_string(),
            b: "FTV0oqNyecdbzY9QFPe5gfiQbSn1E0t+QHn+l+Ey6G2Dk0UZFm1wMsnRbIp5HCneDC+jf6rHCADL1NQ9FIF9o5Td8jObATCRm/YoIoeXY1yFY1rCEoJWFZU0zPeOR7XfBEmccqdMATwb8yznOj6Hn9XqZIr7E3C0XBtzk9GiahLopjP+SN9v/KLEpnLm3dn5FeAp7TcJ0gibi4nNT3u2vziKRNiDIKl71bp6tNC6grCdGOazpkrFSxiYi3QHJOYI".to_string(),
            c: "BEKZboEyoJ3l+DLIF8IMjUR2kJQ9aq2kuXTZR8YizcQMg7zTH0xLO9JtTueneS3JFx1KlK6e2NkFZamiQERujx6bhmwIDgY8ZPCJ8iG//4E3eS0CZ25CJfnOucLeotyr".to_string(),
        };

        // Versuchen Sie, das ungültige Objekt zu deserialisieren
        let deserialized_proof_result = deserialize_proof(&invalid_proof);

        // Überprüfen Sie, ob die Deserialisierung fehlgeschlagen ist
        assert!(deserialized_proof_result.is_err());
    }
}

 */
