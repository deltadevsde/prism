use crate::error::{GeneralError, PrismError};
use anyhow::{anyhow, Context, Result};
use bellman::{groth16, Circuit, ConstraintSystem, SynthesisError};
use bls12_381::{Bls12, Scalar};
use borsh::{BorshDeserialize, BorshSerialize};

pub mod hashchain;
pub mod less_than;
pub mod merkle_batch;
pub mod merkle_insertion;
pub mod merkle_update;
pub mod utils;

pub use hashchain::HashChainEntryCircuit;
pub use less_than::LessThanCircuit;
pub use merkle_batch::BatchMerkleProofCircuit;
pub use merkle_insertion::InsertMerkleProofCircuit;
pub use merkle_update::UpdateMerkleProofCircuit;

#[derive(Clone)]
pub enum ProofVariantCircuit {
    Update(UpdateMerkleProofCircuit),
    Insert(InsertMerkleProofCircuit),
    Batch(BatchMerkleProofCircuit),
}

impl Circuit<Scalar> for ProofVariantCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        match self {
            ProofVariantCircuit::Update(circuit) => circuit.synthesize(cs),
            ProofVariantCircuit::Insert(circuit) => circuit.synthesize(cs),
            ProofVariantCircuit::Batch(circuit) => circuit.synthesize(cs),
        }
    }
}

// G1Affine is a tuple alias of [`bls12_381::G1Affine`] for defining custom conversions.
pub struct G1Affine(bls12_381::G1Affine);

// G2Affine is a tuple alias of [`bls12_381::G2Affine`] for defining custom conversions.
struct G2Affine(bls12_381::G2Affine);

impl TryInto<G1Affine> for [u8; 48] {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<G1Affine> {
        match bls12_381::G1Affine::from_compressed(&self).into_option() {
            Some(affine) => Ok(G1Affine(affine)),
            None => Err(anyhow!(
                GeneralError::DecodingError("G1Affine".to_string(),)
            )),
        }
    }
}

impl From<G1Affine> for bls12_381::G1Affine {
    fn from(affine: G1Affine) -> Self {
        affine.0
    }
}

impl TryInto<G2Affine> for [u8; 96] {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<G2Affine> {
        match bls12_381::G2Affine::from_compressed(&self).into_option() {
            Some(affine) => Ok(G2Affine(affine)),
            None => Err(anyhow!(
                GeneralError::DecodingError("G2Affine".to_string(),)
            )),
        }
    }
}

impl From<G2Affine> for bls12_381::G2Affine {
    fn from(affine: G2Affine) -> Self {
        affine.0
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct Bls12Proof {
    pub a: [u8; 48],
    pub b: [u8; 96],
    pub c: [u8; 48],
}

impl TryFrom<Bls12Proof> for groth16::Proof<Bls12> {
    type Error = anyhow::Error;

    fn try_from(proof: Bls12Proof) -> Result<Self> {
        // we get a CtOption type which is afaik common in crypto libraries to prevent timing attacks
        // we cant use the map_err function with CtOption types so we have to check if its none and can then unwrap it
        let a: G1Affine = proof.a.try_into().context("affine: a")?;
        let b: G2Affine = proof.b.try_into().context("affine: b")?;
        let c: G1Affine = proof.c.try_into().context("affine: c")?;

        Ok(groth16::Proof {
            a: a.into(),
            b: b.into(),
            c: c.into(),
        })
    }
}

impl From<groth16::Proof<Bls12>> for Bls12Proof {
    fn from(proof: groth16::Proof<Bls12>) -> Self {
        Bls12Proof {
            a: proof.a.to_compressed(),
            b: proof.b.to_compressed(),
            c: proof.c.to_compressed(),
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct VerifyingKey {
    pub alpha_g1: [u8; 48],
    pub beta_g1: [u8; 48],
    pub beta_g2: [u8; 96],
    pub delta_g1: [u8; 48],
    pub delta_g2: [u8; 96],
    pub gamma_g2: [u8; 96],
    pub ic: Vec<[u8; 48]>,
}

impl From<groth16::VerifyingKey<Bls12>> for VerifyingKey {
    fn from(verifying_key: groth16::VerifyingKey<Bls12>) -> Self {
        VerifyingKey {
            alpha_g1: verifying_key.alpha_g1.to_compressed(),
            beta_g1: verifying_key.beta_g1.to_compressed(),
            beta_g2: verifying_key.beta_g2.to_compressed(),
            delta_g1: verifying_key.delta_g1.to_compressed(),
            delta_g2: verifying_key.delta_g2.to_compressed(),
            gamma_g2: verifying_key.gamma_g2.to_compressed(),
            ic: verifying_key
                .ic
                .iter()
                .map(|x| x.to_compressed())
                .collect::<Vec<[u8; 48]>>(),
        }
    }
}

impl TryFrom<VerifyingKey> for groth16::VerifyingKey<Bls12> {
    type Error = PrismError;

    fn try_from(custom_vk: VerifyingKey) -> Result<Self, PrismError> {
        let alpha_g1: G1Affine = custom_vk
            .alpha_g1
            .try_into()
            .map_err(|e| GeneralError::EncodingError(format!("{}:alpha_g1", e)))?;
        let beta_g1: G1Affine = custom_vk
            .beta_g1
            .try_into()
            .map_err(|e| GeneralError::EncodingError(format!("{}: beta_g1", e)))?;
        let beta_g2: G2Affine = custom_vk
            .beta_g2
            .try_into()
            .map_err(|e| GeneralError::EncodingError(format!("{}: beta_g2", e)))?;
        let delta_g1: G1Affine = custom_vk
            .delta_g1
            .try_into()
            .map_err(|e| GeneralError::EncodingError(format!("{}: delta_g1", e)))?;
        let delta_g2: G2Affine = custom_vk
            .delta_g2
            .try_into()
            .map_err(|e| GeneralError::EncodingError(format!("{}: delta_g1", e)))?;
        let gamma_g2: G2Affine = custom_vk
            .gamma_g2
            .try_into()
            .map_err(|e| GeneralError::EncodingError(format!("{}: gamma_g2", e)))?;
        let ic = custom_vk
            .ic
            .into_iter()
            .map(|s| s.try_into())
            .collect::<Result<Vec<G1Affine>>>()?;

        Ok(bellman::groth16::VerifyingKey {
            alpha_g1: alpha_g1.into(),
            beta_g1: beta_g1.into(),
            beta_g2: beta_g2.into(),
            gamma_g2: gamma_g2.into(),
            delta_g1: delta_g1.into(),
            delta_g2: delta_g2.into(),
            ic: ic.into_iter().map(|g1| g1.into()).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::utils::hash_to_scalar;
    use super::*;
    use bellman::groth16;
    use bls12_381::Bls12;
    use indexed_merkle_tree::{
        node::Node,
        sha256_mod,
        tree::{IndexedMerkleTree, Proof},
        Hash,
    };
    use rand::rngs::OsRng;

    fn head_scalar() -> Scalar {
        hash_to_scalar(&Node::HEAD).unwrap()
    }

    fn small_scalar() -> Scalar {
        let small_hash =
            Hash::from_hex("13ae3ed6fe76d459c9c66fe38ff187593561a1f24d34cb22e06148c77e4cc02b")
                .unwrap();
        hash_to_scalar(&small_hash).unwrap()
    }

    fn mid_scalar() -> Scalar {
        let mid_hash =
            Hash::from_hex("3d1e830624b2572adc05351a7cbee2d3aa3f6a52b34fa38a260c9c78f96fcd07")
                .unwrap();
        hash_to_scalar(&mid_hash).unwrap()
    }

    fn big_scalar() -> Scalar {
        let big_hash =
            Hash::from_hex("6714dda957170ad7720bbd2c38004152f34ea5d4350a154b84a259cc62a5dbb4")
                .unwrap();
        hash_to_scalar(&big_hash).unwrap()
    }

    fn tail_scalar() -> Scalar {
        hash_to_scalar(&Node::TAIL).unwrap()
    }

    fn create_scalars() -> (Scalar, Scalar, Scalar, Scalar, Scalar) {
        (
            head_scalar(),
            small_scalar(),
            mid_scalar(),
            big_scalar(),
            tail_scalar(),
        )
    }

    fn setup_and_test_less_than_circuit(a: Scalar, b: Scalar) {
        let circuit = LessThanCircuit::new(a, b);
        let rng = &mut OsRng;
        let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng)
            .expect("unable to generate random parameters");
        let proof = groth16::create_random_proof(circuit.clone(), &params, rng)
            .expect("unable to create random proof");
        let pvk = groth16::prepare_verifying_key(&params.vk);
        groth16::verify_proof(&pvk, &proof, &[]).expect("unable to verify proof")
    }

    #[test]
    fn le_with_scalar_valid() {
        let (head, small, mid, big, tail) = create_scalars();

        setup_and_test_less_than_circuit(head, small);
        setup_and_test_less_than_circuit(small, tail);

        setup_and_test_less_than_circuit(small, big);
        setup_and_test_less_than_circuit(big, tail);

        setup_and_test_less_than_circuit(head, mid);
        setup_and_test_less_than_circuit(mid, big);
    }

    #[test]
    #[should_panic(expected = "unable to verify proof")]
    fn invalid_less_than_circuit_a_gt_b() {
        let (_, _, _, big, tail) = create_scalars();

        setup_and_test_less_than_circuit(tail, big)
    }

    #[test]
    #[should_panic(expected = "unable to verify proof")]
    fn invalid_less_than_circuit_a_eq_b() {
        let head = head_scalar();
        setup_and_test_less_than_circuit(head, head)
    }

    #[test]
    fn test_serialize_and_deserialize_proof() {
        let mut tree = IndexedMerkleTree::new_with_size(4).unwrap();
        let prev_commitment = tree.get_commitment().unwrap();

        // create two nodes to insert
        let ryan = sha256_mod(b"Ryan");
        let ford = sha256_mod(b"Ford");
        let sebastian = sha256_mod(b"Sebastian");
        let pusch = sha256_mod(b"Pusch");
        let ethan = sha256_mod(b"Ethan");
        let triple_zero = sha256_mod(b"000");

        let mut ryans_node = Node::new_leaf(true, ryan, ford, Node::TAIL);
        let mut sebastians_node = Node::new_leaf(true, sebastian, pusch, Node::TAIL);
        let mut ethans_node = Node::new_leaf(true, ethan, triple_zero, Node::TAIL);

        // generate proofs for the two nodes
        let first_insert_proof = tree.insert_node(&mut ryans_node).unwrap();
        let second_insert_proof = tree.insert_node(&mut sebastians_node).unwrap();
        let third_insert_proof = tree.insert_node(&mut ethans_node).unwrap();

        // create zkSNARKs for the two proofs
        let first_insert_zk_snark = Proof::Insert(first_insert_proof);
        let second_insert_zk_snark = Proof::Insert(second_insert_proof);
        let third_insert_zk_snark = Proof::Insert(third_insert_proof);

        let proofs = vec![
            first_insert_zk_snark,
            second_insert_zk_snark,
            third_insert_zk_snark,
        ];
        let current_commitment = tree.get_commitment().unwrap();

        let batched_proof =
            BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs).unwrap();

        let rng = &mut OsRng;
        let params =
            groth16::generate_random_parameters::<Bls12, _, _>(batched_proof.clone(), rng).unwrap();
        let proof = groth16::create_random_proof(batched_proof.clone(), &params, rng).unwrap();

        let serialized_proof: Bls12Proof = proof.clone().into();
        let deserialized_proof_result: Result<groth16::Proof<Bls12>> =
            serialized_proof.clone().try_into();
        assert!(deserialized_proof_result.is_ok(), "Deserialization failed");

        let deserialized_proof = deserialized_proof_result.unwrap();
        assert_eq!(proof.a, deserialized_proof.a);
        assert_eq!(proof.b, deserialized_proof.b);
        assert_eq!(proof.c, deserialized_proof.c);
    }

    #[test]
    fn test_deserialize_invalid_proof() {
        let invalid_proof = Bls12Proof {
            a: [1; 48],
            b: [2; 96],
            c: [3; 48],
        };

        let deserialized_proof_result: Result<groth16::Proof<Bls12>> =
            invalid_proof.clone().try_into();
        assert!(deserialized_proof_result.is_err());
    }
}
