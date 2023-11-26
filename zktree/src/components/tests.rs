#![allow(dead_code)]
use crate::{
    components::{leaf_proof::LeafProof, node_proof::NodeProof},
    proof_data::ProofData,
    traits::proof::Proof,
};
#[cfg(tests)]
use crate::{proof_components::node_proof::NodeProof, proof_data::ProofData, traits::proof::Proof};

use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, Sample},
    },
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{Hasher, PoseidonGoldilocksConfig},
    },
};

use super::user_proof::UserProof;

const D: usize = 2;
#[allow(dead_code)]
const VERIFIER_CIRCUIT_DIGEST: [usize; 4] = [
    16829446864742827679,
    2103761447533012528,
    7271535847333132576,
    5716495700162508072,
];
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
#[allow(dead_code)]
type H = PoseidonHash;

#[allow(dead_code)]
fn simple_circuit() -> (F, ProofData<F, C, D>) {
    let mut circuit_builder =
        CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let mut partial_witness = PartialWitness::<F>::new();

    // circuit specification: c = a + b
    let a_target = circuit_builder.add_virtual_target();
    let b_target = circuit_builder.add_virtual_target();

    let sum_target = circuit_builder.add(a_target, b_target);
    let c_target = circuit_builder.add_virtual_target();
    circuit_builder.register_public_input(c_target);

    circuit_builder.connect(c_target, sum_target);

    // fill in values
    let a = F::rand();
    let b = F::rand();
    let c = a + b;

    partial_witness.set_target(a_target, a);
    partial_witness.set_target(b_target, b);
    partial_witness.set_target(c_target, c);

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data
        .prove(partial_witness)
        .expect("Failed to generate proof");

    let proof_data = ProofData {
        circuit_data,
        proof_with_pis,
    };

    (c, proof_data)
}

fn hash_data() -> ([F; 4], HashOut<F>, [F; 4], HashOut<F>) {
    let input_original_data = F::rand_array();
    let input_hash = PoseidonHash::hash_or_noop(&input_original_data);

    let circuit_original_data = F::rand_array();
    let circuit_hash = PoseidonHash::hash_or_noop(&circuit_original_data);

    (
        input_original_data,
        input_hash,
        circuit_original_data,
        circuit_hash,
    )
}

#[allow(dead_code)]
fn simple_circuit_proof_data() -> (
    HashOut<F>,
    HashOut<F>,
    ProofData<F, PoseidonGoldilocksConfig, D>,
) {
    let (input_original_data, input_hash, circuit_original_data, circuit_hash) = hash_data();

    let mut circuit_builder =
        CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut partial_witness = PartialWitness::<F>::new();

    let input_original_data_targets =
        circuit_builder.add_virtual_targets(input_original_data.len());
    let input_hash_targets =
        circuit_builder.hash_or_noop::<PoseidonHash>(input_original_data_targets.clone());

    circuit_builder.register_public_inputs(&input_hash_targets.elements);

    let circuit_original_data_targets =
        circuit_builder.add_virtual_targets(circuit_original_data.len());
    let circuit_hash_targets =
        circuit_builder.hash_or_noop::<PoseidonHash>(circuit_original_data_targets.clone());

    circuit_builder.register_public_inputs(&circuit_hash_targets.elements);

    partial_witness.set_target_arr(&input_original_data_targets, &input_original_data);
    partial_witness.set_hash_target(input_hash_targets, input_hash);

    partial_witness.set_target_arr(&circuit_original_data_targets, &circuit_original_data);
    partial_witness.set_hash_target(circuit_hash_targets, circuit_hash);

    let circuit_data = circuit_builder.build::<PoseidonGoldilocksConfig>();
    let proof_with_pis = circuit_data
        .prove(partial_witness)
        .expect("Failed to prove simple circuit");

    (
        input_hash,
        circuit_hash,
        ProofData {
            proof_with_pis,
            circuit_data,
        },
    )
}

#[test]
fn test_leaf_proof() {
    let (c, proof_data) = simple_circuit();

    let input_hash = PoseidonHash::hash_or_noop(&[c]);
    let circuit_hash = proof_data.circuit_data.verifier_only.circuit_digest;
    let leaf_proof = LeafProof::new(input_hash, circuit_hash, proof_data);

    assert_eq!(leaf_proof.input_hash(), input_hash);
    assert_eq!(
        leaf_proof.circuit_hash(),
        PoseidonHash::hash_or_noop(
            &[
                leaf_proof.circuit_verifier_digest().elements,
                circuit_hash.elements
            ]
            .concat()
        )
    )
}

#[test]
fn test_leaf_proof_2() {
    let (c, proof_data) = simple_circuit();

    let circuit_hash = proof_data.circuit_data.verifier_only.circuit_digest;
    let user_proof = UserProof::new(vec![vec![c]], circuit_hash, proof_data);
    let _leaf_proof = LeafProof::new_from_user_proof(&user_proof)
        .expect("Failed to generate leaf proof from user proof");
}

#[test]
fn test_node_proof() {
    let (left_input_hash, left_circuit_hash, left_proof_data) = simple_circuit_proof_data();
    // let left_circuit_hash= left_proof_data.circuit_data.verifier_only.circuit_digest;
    let left_node_proof = NodeProof::new(left_proof_data, left_input_hash, left_circuit_hash);

    let (right_input_hash, right_circuit_hash, right_proof_data) = simple_circuit_proof_data();
    // let right_circuit_hash = right_proof_data.circuit_data.verifier_only.circuit_digest;
    let right_node_proof = NodeProof::new(right_proof_data, right_input_hash, right_circuit_hash);

    let result_node_proof = NodeProof::new_from_children(&left_node_proof, &right_node_proof);

    // assert!(result_node_proof.is_ok());

    let node_proof = result_node_proof.expect("Failed to generate proof");

    // verify that the `NodeProof`'s input and circuit hashes are correct
    let should_be_input_hash =
        H::hash_or_noop(&[left_input_hash.elements, right_input_hash.elements].concat());

    assert_eq!(node_proof.input_hash(), should_be_input_hash);

    let should_be_circuit_hash = H::hash_or_noop(
        &[
            left_circuit_hash.elements,
            VERIFIER_CIRCUIT_DIGEST.map(|x| F::from_canonical_usize(x)),
            right_circuit_hash.elements,
        ]
        .concat(),
    );
    assert_eq!(node_proof.circuit_hash(), should_be_circuit_hash);
}
