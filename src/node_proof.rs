use anyhow::{anyhow, Error};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use std::marker::PhantomData;

use crate::proof_data::ProofData;

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
    pub fn new_from_node_proofs(
        node_proof_1: NodeProof<C, F, H, D>,
        node_proof_2: NodeProof<C, F, H, D>,
    ) -> Result<Self, Error> {
        let node_input_hash_1 = node_proof_1.input_hash;
        let node_input_hash_2 = node_proof_2.input_hash;
        let input_hash =
            H::hash_no_pad(&[node_input_hash_1.elements, node_input_hash_2.elements].concat());

        let node_circuit_hash_1 = node_proof_1.circuit_hash;
        let node_circuit_hash_2 = node_proof_2.circuit_hash;
        let node_verifier_data_hash_1 = node_proof_1
            .proof_data
            .circuit_data
            .verifier_only
            .circuit_digest;
        let node_verifier_data_hash_2 = node_proof_2
            .proof_data
            .circuit_data
            .verifier_only
            .circuit_digest;

        if node_verifier_data_hash_1 != node_circuit_hash_2 {
            return Err(anyhow!(
                "Invalid circuit verifier data for node 1 and node 2"
            ));
        }

        let circuit_hash = H::hash_no_pad(
            &[
                node_circuit_hash_1.elements,
                node_verifier_data_hash_1.elements,
                node_circuit_hash_2.elements,
            ]
            .concat(),
        );

        Ok(Self {
            input_hash,
            circuit_hash,
            proof_data,
        })
    }
}
