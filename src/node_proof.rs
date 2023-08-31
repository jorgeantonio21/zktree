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
    pub fn new<P: Proof<C, F, D>>(node_proof_1: P, node_proof_2: P) -> Result<Self, Error> {
        let node_input_hash_1 = node_proof_1.input_hash();
        let node_input_hash_2 = node_proof_2.input_hash();
        let input_hash =
            H::hash_no_pad(&[node_input_hash_1.elements, node_input_hash_2.elements].concat());

        let node_circuit_hash_1 = node_proof_1.circuit_hash();
        let node_circuit_hash_2 = node_proof_2.circuit_hash();
        let node_verifier_data_hash_1 = node_proof_1
            .proof()
            .circuit_data
            .verifier_only
            .circuit_digest;
        let node_verifier_data_hash_2 = node_proof_2
            .proof()
            .circuit_data
            .verifier_only
            .circuit_digest;

        if node_verifier_data_hash_1 != node_verifier_data_hash_2 {
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

        let node_circuit = NodeCircuit::new(node_proof_1, node_proof_2);
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
