use std::marker::PhantomData;

use anyhow::Error;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::{AlgebraicHasher, GenericConfig, Hasher},
};

use crate::{
    leaf_circuit::LeafCircuit,
    proof_data::ProofData,
    traits::{provable::Provable, tree_proof::Proof},
    user_proof::UserProof,
};

pub struct LeafProof<C, F, H, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
{
    hash_user_public_inputs: HashOut<F>,
    user_circuit_hash: HashOut<F>,
    proof_data: ProofData<F, C, D>,
    _phantom_data: PhantomData<H>,
}

impl<C, F, H, const D: usize> LeafProof<C, F, H, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    pub fn new(
        hash_user_public_inputs: HashOut<F>,
        user_circuit_hash: HashOut<F>,
        proof_data: ProofData<F, C, D>,
    ) -> Self {
        Self {
            hash_user_public_inputs,
            user_circuit_hash,
            proof_data,
            _phantom_data: PhantomData,
        }
    }

    pub fn new_from_user_proof(user_proof: UserProof<C, F, D>) -> Result<Self, Error> {
        let user_proof_public_inputs = user_proof.user_public_inputs();
        let hash_user_public_inputs =
            PoseidonHash::hash_or_noop(&user_proof_public_inputs.concat());
        let user_circuit_hash = user_proof.circuit_hash();

        let leaf_circuit = LeafCircuit::new(user_proof);
        let proof_data = leaf_circuit.proof()?;
        Ok(Self {
            hash_user_public_inputs,
            proof_data,
            user_circuit_hash,
            _phantom_data: PhantomData,
        })
    }
}

impl<C, F, H, const D: usize> Proof<C, F, D> for LeafProof<C, F, H, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    fn circuit_hash(&self) -> HashOut<F> {
        let user_circuit_hash = self.user_circuit_hash;
        let circuit_verifier_hash = self.circuit_verifier_digest();
        PoseidonHash::hash_or_noop(
            &[user_circuit_hash.elements, circuit_verifier_hash.elements].concat(),
        )
    }

    fn circuit_verifier_digest(&self) -> HashOut<F> {
        self.proof_data.circuit_data.verifier_only.circuit_digest
    }

    fn input_hash(&self) -> HashOut<F> {
        self.hash_user_public_inputs
    }

    fn proof(&self) -> &ProofData<F, C, D> {
        &self.proof_data
    }

    fn user_public_inputs(&self) -> Vec<&[F]> {
        vec![]
    }
}
