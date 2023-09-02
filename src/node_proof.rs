use anyhow::{anyhow, Error};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use std::marker::PhantomData;

use crate::{
    node_circuit::NodeCircuit, proof_data::ProofData, provable::Provable, tree_proof::Proof,
};

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

    pub fn new_from_children<P: Proof<C, F, D>>(
        left_node_proof: P,
        right_node_proof: P,
        verifier_circuit_digest: H::Hash,
    ) -> Result<Self, Error> {
        let left_node_input_hash = left_node_proof.input_hash();
        let right_node_input_hash = right_node_proof.input_hash();
        let input_hash = H::hash_no_pad(
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

        // TODO: this is duplicate code, should be removed
        let circuit_hash = H::hash_no_pad(
            &[
                left_node_circuit_hash.elements,
                verifier_circuit_digest.elements,
                right_node_circuit_hash.elements,
            ]
            .concat(),
        );

        let node_circuit =
            NodeCircuit::new(left_node_proof, right_node_proof, verifier_circuit_digest);
        let proof_data = node_circuit.proof()?;

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
    fn circuit_hash(&self) -> HashOut<F> {
        self.circuit_hash
    }

    fn input_hash(&self) -> HashOut<F> {
        self.input_hash
    }

    fn proof(&self) -> &ProofData<F, C, D> {
        &self.proof_data
    }

    fn verifier_data(&self) -> HashOut<F> {
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
        9655690328080666940,
        3467578314769302625,
        1856731120987587081,
        4882619829583239639,
    ];
    type F = GoldilocksField;

    fn hash_data() -> ([F; 4], HashOut<F>, [F; 4], HashOut<F>) {
        let input_original_data = F::rand_array();
        let input_hash = PoseidonHash::hash_no_pad(&input_original_data);

        let circuit_original_data = F::rand_array();
        let circuit_hash = PoseidonHash::hash_no_pad(&circuit_original_data);

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
        let input_hash_targets = circuit_builder
            .hash_n_to_hash_no_pad::<PoseidonHash>(input_original_data_targets.clone());

        circuit_builder.register_public_inputs(&input_hash_targets.elements);

        let circuit_original_data_targets =
            circuit_builder.add_virtual_targets(circuit_original_data.len());
        let circuit_hash_targets = circuit_builder
            .hash_n_to_hash_no_pad::<PoseidonHash>(circuit_original_data_targets.clone());

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
        let (input_hash, circuit_hash, left_proof_data) = simple_circuit_proof_data();
        // let left_circuit_hash= left_proof_data.circuit_data.verifier_only.circuit_digest;
        let left_node_proof = NodeProof {
            proof_data: left_proof_data,
            input_hash,
            circuit_hash,
            phantom_data: PhantomData,
        };

        let (input_hash, circuit_hash, right_proof_data) = simple_circuit_proof_data();
        // let right_circuit_hash = right_proof_data.circuit_data.verifier_only.circuit_digest;
        let right_node_proof = NodeProof {
            proof_data: right_proof_data,
            input_hash,
            circuit_hash,
            phantom_data: PhantomData,
        };

        let verifier_circuit_digest = VERIFIER_CIRCUIT_DIGEST.map(|x| F::from_canonical_usize(x));
        let node_proof = NodeProof::new_from_children(
            left_node_proof,
            right_node_proof,
            HashOut {
                elements: verifier_circuit_digest,
            },
        )
        .expect("Failed to generate node proof");

        println!(
            "FLAG: DEBUG circuit_hash = {:?}",
            node_proof
                .proof_data
                .circuit_data
                .verifier_only
                .circuit_digest
        );
    }
}
