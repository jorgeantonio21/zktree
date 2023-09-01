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
    pub fn new<P: Proof<C, F, D>>(left_node_proof: P, right_node_proof: P) -> Result<Self, Error> {
        let node_input_hash_1 = left_node_proof.input_hash();
        let node_input_hash_2 = right_node_proof.input_hash();
        let input_hash =
            H::hash_no_pad(&[node_input_hash_1.elements, node_input_hash_2.elements].concat());

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

        let circuit_hash = H::hash_no_pad(
            &[
                left_node_circuit_hash.elements,
                left_node_verifier_data_hash.elements,
                right_node_circuit_hash.elements,
            ]
            .concat(),
        );

        let node_circuit = NodeCircuit::new(left_node_proof, right_node_proof);
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
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::poseidon::PoseidonHash,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{Hasher, PoseidonGoldilocksConfig},
        },
    };

    use crate::node_circuit;

    use super::*;

    const D: usize = 2;
    type F = GoldilocksField;

    fn simple_circuit_proof_data() -> ProofData<F, PoseidonGoldilocksConfig, D> {
        let input_original_data = [F::ONE, F::ZERO, F::ONE, F::ZERO];
        let input_hash = PoseidonHash::hash_no_pad(&input_original_data);

        let circuit_original_data = [F::ZERO, F::ONE, F::ZERO, F::ONE];
        let circuit_hash = PoseidonHash::hash_no_pad(&circuit_original_data);

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

        ProofData {
            proof_with_pis,
            circuit_data,
        }
    }

    #[test]
    fn test_node_proof() {
        let left_proof_data = simple_circuit_proof_data();

        let input_hash = PoseidonHash::hash_no_pad(&[F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
        let circuit_hash = PoseidonHash::hash_no_pad(&[F::ONE, F::ONE, F::ONE, F::ONE]);

        let left_node_proof = NodeProof {
            proof_data: left_proof_data,
            input_hash,
            circuit_hash,
            phantom_data: PhantomData,
        };

        let right_node_proof = simple_circuit_proof_data();
        let right_node_proof = NodeProof {
            proof_data: right_node_proof,
            input_hash,
            circuit_hash,
            phantom_data: PhantomData,
        };

        assert!(NodeProof::new(left_node_proof, right_node_proof).is_ok());
    }
}
