use anyhow::{anyhow, Error};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use std::marker::PhantomData;

use crate::{
    components::node_circuit::NodeCircuit,
    proof_data::ProofData,
    traits::{proof::Proof, provable::Provable},
};

/// `NodeProof` represents proof data for an internal node in a zkTree structure. It holds the combined proof data of the node's children
/// and the respective hashes of their inputs and circuits. This struct is essential for constructing
/// and verifying a proof that spans multiple levels of a circuit hierarchy.
///
/// # Type Parameters
///
/// * `C`: The configuration of the circuit, which must implement `GenericConfig`.
/// * `F`: The field type that implements `RichField` and `Extendable<D>`, used for cryptographic operations within the circuit.
/// * `H`: The hasher type that implements `AlgebraicHasher<F>`, utilized for generating cryptographic hashes.
/// * `D`: The dimension of the field extension, specified as a compile-time constant.
///
/// # Fields
///
/// * `proof_data`: The combined proof data of this node's children.
/// * `input_hash`: The hash of the inputs to this node's circuit.
/// * `circuit_hash`: The hash of this node's circuit.
/// * `phantom_data`: `PhantomData` to mark the usage of the hasher type `H`.
pub struct NodeProof<C, F, H, const D: usize>
where
    H: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
{
    proof_data: ProofData<F, C, D>,
    input_hash: HashOut<F>,
    circuit_hash: HashOut<F>,
    phantom_data: PhantomData<H>,
}

impl<C, F, H, const D: usize> NodeProof<C, F, H, D>
where
    H: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
{
    /// Creates a new `NodeProof` instance using the provided proof data, input hash, and circuit hash.
    ///
    /// # Arguments
    ///
    /// * `proof_data`: The proof data for this node.
    /// * `input_hash`: The hash of the inputs for this node.
    /// * `circuit_hash`: The hash of this node's circuit.
    ///
    /// # Returns
    ///
    /// A new `NodeProof` instance.
    pub fn new(
        proof_data: ProofData<F, C, D>,
        input_hash: HashOut<F>,
        circuit_hash: HashOut<F>,
    ) -> Self {
        Self {
            proof_data,
            input_hash,
            circuit_hash,
            phantom_data: PhantomData,
        }
    }

    /// Constructs a new `NodeProof` from the proof data of its child nodes. It hashes the inputs
    /// and circuits of the children to create a new aggregated hash for this node. This method also
    /// verifies that the children share the same circuit verifier data.
    ///
    /// # Arguments
    ///
    /// * `left_node_proof`: A reference to the proof of the left child node.
    /// * `right_node_proof`: A reference to the proof of the right child node.
    ///
    /// # Returns
    ///
    /// A `Result` that, upon success, contains the new `NodeProof` instance, or an `Error` if the child nodes
    /// have mismatched verifier data or if the proof generation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the circuit verifier data of the child nodes do not match or if the proof generation fails.
    pub fn new_from_children<'a, P: Proof<C, F, D>>(
        left_node_proof: &'a P,
        right_node_proof: &'a P,
    ) -> Result<Self, Error> {
        let left_node_input_hash = left_node_proof.input_hash();
        let right_node_input_hash = right_node_proof.input_hash();
        let input_hash = H::hash_or_noop(
            &[
                left_node_input_hash.elements,
                right_node_input_hash.elements,
            ]
            .concat(),
        );

        let left_node_circuit_hash = left_node_proof.circuit_hash();
        let right_node_circuit_hash = right_node_proof.circuit_hash();
        let left_node_verifier_data_hash = left_node_proof
            .proof()
            .circuit_data
            .verifier_only
            .circuit_digest;
        let right_node_verifier_data_hash = right_node_proof
            .proof()
            .circuit_data
            .verifier_only
            .circuit_digest;

        if left_node_verifier_data_hash != right_node_verifier_data_hash {
            return Err(anyhow!(
                "Invalid circuit verifier data for node 1 and node 2"
            ));
        }

        let node_circuit = NodeCircuit::new(left_node_proof, right_node_proof);
        let proof_data = node_circuit.proof()?;

        let verifier_circuit_digest = proof_data.circuit_data.verifier_only.circuit_digest;

        // TODO: this is duplicate code, should be removed
        let circuit_hash = H::hash_or_noop(
            &[
                left_node_circuit_hash.elements,
                verifier_circuit_digest.elements,
                right_node_circuit_hash.elements,
            ]
            .concat(),
        );

        Ok(Self {
            input_hash,
            circuit_hash,
            proof_data,
            phantom_data: PhantomData,
        })
    }
}

impl<C, F, H, const D: usize> Proof<C, F, D> for NodeProof<C, F, H, D>
where
    C: GenericConfig<D, F = F, Hasher = H>,
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
{
    fn user_public_inputs(&self) -> Vec<&[F]> {
        vec![]
    }

    fn circuit_hash(&self) -> HashOut<F> {
        self.circuit_hash
    }

    fn input_hash(&self) -> HashOut<F> {
        self.input_hash
    }

    fn proof(&self) -> &ProofData<F, C, D> {
        &self.proof_data
    }

    fn circuit_verifier_digest(&self) -> HashOut<F> {
        self.proof().circuit_data.verifier_only.circuit_digest
    }
}

#[cfg(test)]
mod tests {

    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, Sample},
        },
        hash::poseidon::PoseidonHash,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{Hasher, PoseidonGoldilocksConfig},
        },
    };

    use super::*;

    const D: usize = 2;
    const VERIFIER_CIRCUIT_DIGEST: [usize; 4] = [
        16829446864742827679,
        2103761447533012528,
        7271535847333132576,
        5716495700162508072,
    ];
    type F = GoldilocksField;
    type H = PoseidonHash;

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
    fn test_node_proof() {
        let (left_input_hash, left_circuit_hash, left_proof_data) = simple_circuit_proof_data();
        // let left_circuit_hash= left_proof_data.circuit_data.verifier_only.circuit_digest;
        let left_node_proof = NodeProof {
            proof_data: left_proof_data,
            input_hash: left_input_hash,
            circuit_hash: left_circuit_hash,
            phantom_data: PhantomData,
        };

        let (right_input_hash, right_circuit_hash, right_proof_data) = simple_circuit_proof_data();
        // let right_circuit_hash = right_proof_data.circuit_data.verifier_only.circuit_digest;
        let right_node_proof = NodeProof {
            proof_data: right_proof_data,
            input_hash: right_input_hash,
            circuit_hash: right_circuit_hash,
            phantom_data: PhantomData,
        };

        let result_node_proof = NodeProof::new_from_children(&left_node_proof, &right_node_proof);

        // assert!(result_node_proof.is_ok());

        let node_proof = result_node_proof.expect("Failed to generate proof");

        // verify that the `NodeProof`'s input and circuit hashes are correct
        let should_be_input_hash =
            H::hash_or_noop(&[left_input_hash.elements, right_input_hash.elements].concat());

        assert_eq!(node_proof.input_hash, should_be_input_hash);

        let should_be_circuit_hash = H::hash_or_noop(
            &[
                left_circuit_hash.elements,
                VERIFIER_CIRCUIT_DIGEST.map(|x| F::from_canonical_usize(x)),
                right_circuit_hash.elements,
            ]
            .concat(),
        );
        assert_eq!(node_proof.circuit_hash, should_be_circuit_hash);
    }
}
